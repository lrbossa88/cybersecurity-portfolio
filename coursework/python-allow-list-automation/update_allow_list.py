# Updates an allow list file by removing IP addresses that no longer have access.
# Google Cybersecurity Certificate, Course 7 lab. I wrapped my steps in a function
# so it can be reused without rewriting the script.

def update_allow_list(import_file, remove_list):
    # Open the file and read its contents into a string
    with open(import_file, "r") as file:
        ip_addresses = file.read()

    # Convert the string into a list so single IPs can be removed
    ip_addresses = ip_addresses.split()

    # Go through the remove list and take out any IP that's on the allow list
    for element in remove_list:
        if element in ip_addresses:
            ip_addresses.remove(element)

    # Turn the list back into a string, one IP per line
    ip_addresses = "\n".join(ip_addresses)

    # Rewrite the original file with the updated list
    with open(import_file, "w") as file:
        file.write(ip_addresses)


if __name__ == "__main__":
    # Example run using the sample file in this folder
    remove_list = ["192.168.97.225", "192.168.158.170", "192.168.201.40", "192.168.58.57"]
    update_allow_list("sample_allow_list.txt", remove_list)
