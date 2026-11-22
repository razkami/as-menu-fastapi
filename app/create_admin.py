import getpass,re,sqlite3
from datetime import datetime,timezone
from app.main import connect,initialize,hash_password
def main():
 initialize()
 email=input("Әкімшінің пошта адресі: ").strip().lower()
 if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email):raise SystemExit("Пошта пішімі дұрыс емес.")
 p=getpass.getpass("Құпиясөз (кемінде 10 таңба): ")
 if len(p)<10:raise SystemExit("Құпиясөз кемінде 10 таңба болуы керек.")
 if p!=getpass.getpass("Құпиясөзді қайталаңыз: "):raise SystemExit("Құпиясөз сәйкес емес.")
 try:
  with connect() as db:db.execute("INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,'admin',?)",(email,hash_password(p),datetime.now(timezone.utc).isoformat()))
 except sqlite3.IntegrityError:raise SystemExit("Бұл пошта тіркелген.")
 print("Әкімші аккаунты дайын.")
if __name__=="__main__":main()

