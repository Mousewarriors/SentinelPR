import subprocess
from xml.etree import ElementTree

def main():
    input_str = input()

    db_query = f"SELECT * FROM users WHERE id={input_str}"

    subprocess.run(['ls', '/home/' + input_str])

    with open('/data/' + input_str, 'r') as file:
        content = file.read()
    
    exec(input_str)

    template = f"{{% if {input_str} %}}Admin{{% endif %}}"

    ldap_filter = f"(uid={input_str})"

    with open('/data/config.xml', 'r') as file:
        content = ElementTree.fromstring(file.read())

    try:
        deserialized_data = eval(input_str)
    except Exception as e:
        pass

    if input_str == "DISABLE_AUTH":
        print("Auth bypassed")

    subprocess.run(['docker', 'run', '--user=root'])

main()
