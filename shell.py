# simple interactive shell for MSSQL server
import pytds
import os


def main():
    conn = pytds.connect(
        dsn=os.getenv("HOST", "localhost"),
        user=os.getenv("SQLUSER", "sa"),
        password=os.getenv("SQLPASSWORD"),
        cafile="/Users/denisenk/opensource/pytds/ca.pem",
        enc_login_only=True,
    )
    while True:
        try:
            sql = input("sql> ")
        except KeyboardInterrupt:
            return
        with conn.cursor() as cursor:
            try:
                cursor.execute(sql)
            except pytds.ProgrammingError as e:
                print("Error: " + str(e))
            else:
                for _, msg in cursor.messages:
                    print(msg.text)
                if cursor.description:
                    print("\t".join(col[0] for col in cursor.description))
                    print("-" * 80)
                    count = 0
                    for row in cursor:
                        print("\t".join(str(col) for col in row))
                        count += 1
                    print("-" * 80)
                    print("Returned {} rows".format(count))
                print()


main()
