import sqlite3
import vuln
import os.path

DBFILE = 'vulnDB.db'

def createDB():
    conn = sqlite3.connect(DBFILE)
    command = "CREATE TABLE 'Vuls' ('id' INTEGER,'title' TEXT, 'time_create' TEXT," \
              "'time_change'	TEXT,	'risk_value'	TEXT,	'risk_name'	TEXT," \
              "	'cve_id'	TEXT,	'time_release'	TEXT,PRIMARY KEY('id'));"
    c = conn.cursor()
    c.execute(command)
    conn.commit()
    conn.close()

##If the DB doesnt exist create it
if not os.path.isfile(DBFILE):
    createDB()

conn = sqlite3.connect(DBFILE)
c = conn.cursor()

def write(vuln):
    try:
        c.execute("INSERT INTO Vuls VALUES (?,?,?,?,?,?,?,?)",(vuln.id,vuln.title,vuln.time_create,vuln.time_change,vuln.risk_value,vuln.risk_name,vuln.cve_id,vuln.time_release))
        conn.commit()
    except Exception:
        pass

def get_vuln_byID(id):
    conn = sqlite3.connect('vulnDB.db')
    c = conn.cursor()
    c.execute("SELECT * from Vuls WHERE id = (?)",(id,))
    x = c.fetchone()
    if x is None:
        return None
    else:
        v = vuln.Vuln()
        v.vulDBbuild(x)
        return x

def read():
    c.execute("SELECT * from Vuls")
    for row in c:
        v = vuln.Vuln()
        v.vulDBbuild(row)
        yield v

