package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"fmt"
	"io"
	"iter"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type AnonymizerCodeword struct {
	codeword     string
	hostnameList []string
	domainList   []string
	hash         [32]byte
	statistics   *Statistics
}

func NewAnonymizerCodeword(codeword string) *AnonymizerCodeword {
	return &AnonymizerCodeword{
		codeword: codeword,
		hash:     sha256.Sum256([]byte(codeword)),
	}
}

func (a *AnonymizerCodeword) SetStatistics(statistics *Statistics) *AnonymizerCodeword {
	a.statistics = statistics
	return a
}

func (a *AnonymizerCodeword) AddHostname(hostname string) *AnonymizerCodeword {
	a.hostnameList = append(a.hostnameList, hostname)
	return a
}

func (a *AnonymizerCodeword) AddDomain(domain string) *AnonymizerCodeword {
	a.domainList = append(a.domainList, domain)
	return a
}

func (a *AnonymizerCodeword) IP(ipString string) string {
	ip := net.ParseIP(ipString)
	if ip == nil {
		return ipString
	}
	ip = ip.To4()
	if ip == nil {
		//fmt.Println("Not an IPv4 address")
		return ipString
	}
	if ip[0] == 10 {
		value := fmt.Sprintf("10.%d.%d.%d", ip[1]^a.hash[1], ip[2]^a.hash[2], ip[3]^a.hash[3])
		if a.statistics != nil {
			a.statistics.Add(ipString, value)
		}
		return value
	}
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		value := fmt.Sprintf("172.%d.%d.%d", (ip[1]^a.hash[1])&0x1F, ip[2]^a.hash[2], ip[3]^a.hash[3])
		if a.statistics != nil {
			a.statistics.Add(ipString, value)
		}
		return value
	}
	if ip[0] == 192 && ip[1] == 168 {
		value := fmt.Sprintf("192.168.%d.%d", ip[2]^a.hash[2], ip[3]^a.hash[3])
		if a.statistics != nil {
			a.statistics.Add(ipString, value)
		}
		return value
	}
	return ipString
}

func Encode(d []byte) string {
	encoder := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")
	return encoder.EncodeToString(d)
}

func (a *AnonymizerCodeword) Hostname(hostname string) string {
	hash := sha256.Sum256([]byte(a.codeword + hostname))
	value := "H" + Encode(hash[:])[:8]
	if a.statistics != nil {
		a.statistics.Add(hostname, value)
	}
	return value
}

func (a *AnonymizerCodeword) Domain(domain string) string {
	hash := sha256.Sum256([]byte(a.codeword + domain))
	return "D" + Encode(hash[:])[:8]
}

func (a *AnonymizerCodeword) AnonymyzeIPs(data string) string {
	return privateIPRegex.ReplaceAllStringFunc(data, func(match string) string {
		return a.IP(match)
	})
}

func (a *AnonymizerCodeword) CheckSuffix(user, found []string) bool {
	for i := 0; i < len(found); i++ {
		u := len(user) - i - 1
		f := len(found) - i - 1
		if u >= 0 {
			if user[u] != found[f] {
				return false
			}
		} else {
			found[f] = a.Domain(found[f])
		}
	}
	if a.statistics != nil {
		a.statistics.Add(strings.Join(user, "."),
			strings.Join(found, "."),
		)
	}

	return true
}

func (a *AnonymizerCodeword) AnonymizeDomains(data string) string {
	regex := `\b([a-zA-Z][a-zA-Z0-9-]+(?:\.[a-zA-Z][a-zA-Z0-9-]+)+)\b`
	r := regexp.MustCompile(regex)
	return r.ReplaceAllStringFunc(data, func(match string) string {
		return a.AnonymizeDomain(match)
	})
}

func (a *AnonymizerCodeword) AnonymizeDomain(domain string) string {
	for _, userDomain := range a.domainList {
		user := strings.Split(userDomain, ".")
		found := strings.Split(domain, ".")
		if a.CheckSuffix(user, found) {
			return strings.Join(found, ".")
		}
	}
	return domain
}

func (a *AnonymizerCodeword) AnonymizeHostnames(data string) string {
	regexStr := fmt.Sprintf("(?i)(%s)", strings.Join(a.hostnameList, "|"))
	re := regexp.MustCompile(regexStr)
	return re.ReplaceAllStringFunc(data, func(match string) string {
		return a.Hostname(match)
	})
}

func (a *AnonymizerCodeword) AnonymizeString(data string) string {
	data = a.AnonymyzeIPs(data)
	if len(a.hostnameList) > 0 {
		data = a.AnonymizeHostnames(data)
	}
	if len(a.domainList) > 0 {
		data = a.AnonymizeDomains(data)
	}
	return data
}

func (a *AnonymizerCodeword) FilterFilenames(dst io.Writer, src io.Reader) error {
	var sb strings.Builder
	_, err := io.Copy(&sb, src)
	if err != nil {
		return fmt.Errorf("failed to copy file contents: %v", err)
	}
	if strings.HasPrefix(sb.String(), SQLitePrefix) {
		return a.AnonymizeSQLite(dst, []byte(sb.String()))
	}
	resultData := a.AnonymizeString(sb.String())
	_, err = dst.Write([]byte(resultData))
	if err != nil {
		return fmt.Errorf("failed to write file contents: %v", err)
	}
	return nil
}

func (a *AnonymizerCodeword) AnonymizeSQLite(dst io.Writer, data []byte) error {
	tempDir, err := os.MkdirTemp("", "dsab-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	fileName := "temp.sqlite"
	filePath := filepath.Join(tempDir, fileName)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return err
	}
	if err := a.FilterSQLite(filePath); err != nil {
		return err
	}
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(dst, file)
	return err
}

func (a *AnonymizerCodeword) FilterSQLite(database string) error {
	db, err := sql.Open("sqlite3", database)
	if err != nil {
		return err
	}
	defer db.Close()
	for tableName, err := range SQLiteIterateTables(db) {
		if err != nil {
			return err
		}
		if err := a.FilterSQLiteTable(db, tableName); err != nil {
			return err
		}
	}
	return nil
}

func (a *AnonymizerCodeword) FilterSQLiteTable(db *sql.DB, tableName string) error {
	textColumns, err := SQLiteTableColumns(db, tableName)
	if err != nil {
		return err
	}
	if len(textColumns) == 0 {
		return nil
	}
	query := fmt.Sprintf("SELECT %s FROM %s", strings.Join(textColumns, ", "), tableName)
	dataRows, err := db.Query(query)
	if err != nil {
		return err
	}
	defer dataRows.Close()
	columns := make([]string, len(textColumns))
	columnPointers := make([]interface{}, len(textColumns))
	for i := range columns {
		columnPointers[i] = &columns[i]
	}

	for dataRows.Next() {
		if err := dataRows.Scan(columnPointers...); err != nil {
			return err
		}
		updatedColumns := make([]string, len(textColumns))
		updateNeeded := false
		for i := range textColumns {
			updatedColumns[i] = a.AnonymizeString(columns[i])
			if updatedColumns[i] != columns[i] {
				updateNeeded = true
			}
		}
		if updateNeeded {
			var set []string
			for i := range textColumns {
				set = append(set, fmt.Sprintf("%s = '%s'", textColumns[i], updatedColumns[i]))
			}
			s := strings.Join(set, ", ")
			var where []string
			for i := range textColumns {
				where = append(where, fmt.Sprintf("%s = '%s'", textColumns[i], columns[i]))
			}
			w := strings.Join(where, " AND ")
			updateQuery := fmt.Sprintf("UPDATE %s SET %s WHERE %s", tableName, s, w) //  set[:len(set)-2], where[:len(where)-5])
			if _, err := db.Exec(updateQuery); err != nil {
				return err
			}
		}

	}
	return nil
}

func SQLiteIterateTables(db *sql.DB) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		rows, err := db.Query("SELECT name FROM sqlite_master WHERE type='table'")
		if err != nil {
			yield("", err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var tableName string
			if err := rows.Scan(&tableName); err != nil {
				if err != nil {
					yield("", err)
					return
				}
			}
			if !yield(tableName, nil) {
				return
			}
		}
	}
}

func SQLiteTableColumns(db *sql.DB, tableName string) ([]string, error) {
	columnRows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%s)", tableName))
	if err != nil {
		return nil, err
	}
	defer columnRows.Close()
	var result []string
	for columnRows.Next() {
		var (
			cid       int
			name      string
			dataType  string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := columnRows.Scan(&cid, &name, &dataType, &notNull, &dfltValue, &pk); err != nil {
			return nil, err
		}
		result = append(result, name)
	}
	return result, nil
}
