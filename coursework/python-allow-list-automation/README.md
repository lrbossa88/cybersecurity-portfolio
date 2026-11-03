# Python Allow List Automation

*Google Cybersecurity Certificate coursework*

There's a file called `allow_list.txt` with IP addresses that are allowed to access sensitive content, and a second list of IPs that should no longer have access. Instead of editing the file by hand, I wrote a Python algorithm that removes those IPs from the allow list automatically.

**Files:**
- [update_allow_list.py](update_allow_list.py) - the script
- [sample_allow_list.txt](sample_allow_list.txt) - example allow list to test it with

## How it works

### 1. Open the file

```python
import_file = "allow_list.txt"

with open(import_file, "r") as file:
```

I stored the file name in `import_file`, then used a `with` statement to open it. `"r"` opens it in read mode. `as file` stores the opened file in a variable called `file`. Using `with` also closes the file automatically when it's done.

### 2. Read the contents

```python
    ip_addresses = file.read()
```

`.read()` turns the whole file into one string, and I saved it in `ip_addresses`.

### 3. Convert the string into a list

```python
ip_addresses = ip_addresses.split()
```

To remove single IPs, it needs to be a list. `.split()` breaks the string apart at every space or new line, so each IP becomes its own item.

### 4. Loop through the remove list and take out matches

```python
for element in remove_list:
    if element in ip_addresses:
        ip_addresses.remove(element)
```

The `for` loop goes through every IP in `remove_list` one at a time, using `element` as the loop variable. The `if` checks that the IP is actually on the allow list before removing it. Without that check, `.remove()` throws an error if the IP isn't there.

### 5. Convert it back to a string

```python
ip_addresses = "\n".join(ip_addresses)
```

`.join()` puts the list back together as one string. `"\n"` puts each IP on its own line so the file looks the same as before.

### 6. Write the updated list back to the file

```python
with open(import_file, "w") as file:
    file.write(ip_addresses)
```

Opening with `"w"` (write mode) replaces whatever was in the file with the new list, so the removed IPs are gone.

## Making it reusable

In the final script I wrapped all of this in a function, `update_allow_list(import_file, remove_list)`. That way it can be run again any time the remove list changes without rewriting anything.

I tested it on the sample file: 4 IPs in the remove list, 3 of them were on the allow list and got removed, and the one that wasn't on the list got skipped without any errors.

## Why this matters for security

Keeping allow lists up to date is part of access control. If someone's access gets revoked but their IP stays on the allow list, they can still get in. Automating it means it actually gets done every time, and done the same way, instead of relying on someone to remember to edit a file.
