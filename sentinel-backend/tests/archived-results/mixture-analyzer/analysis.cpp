#include <iostream>
#include <string>
#include <fstream>

int main() {
    std::string input;
    getline(std::cin, input);

    const char* db_query = "SELECT * FROM users WHERE id=" + input;

    std::system(("ls /home/" + input).c_str());

    std::ifstream file("/data" + input);
    if (file.is_open()) {
        std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();
    }

    const char* raw_query = "queryRawUnsafe(" + input + ")";

    const char* mongo_query = "$where=" + input;

    const char* ldap_filter = "(uid=" + input + ")";

    std::ifstream xml_file("/data/config.xml");
    if (xml_file.is_open()) {
        std::string content((std::istreambuf_iterator<char>(xml_file)), std::istreambuf_iterator<char>());
        xml_file.close();
    }

    const char* deserialized_data = input.c_str();

    system("kubectl run --image=privileged:image");

    system("docker run --network host -it bash");

    return 0;
}
