import asyncio
from truecallerpy import search_phonenumber

phone_number = "02488811774"
country_code = "VN"
installation_id = "a1i0I--jMM3uXFb-ofc-ODmqyAGq8gHtLFxVeOdmifPv9kJWNeNABir5r72aykMM"

response = asyncio.run(search_phonenumber(phone_number, country_code, installation_id))
# print(response['data'][0]['name'])

# print(response)
# Accessing the 'name' value

try:
    name_value = response['data']['data'][0]['name']
    if name_value:
        print(name_value)
except KeyError:
    # Handling the specific exception
    name_value = "normal"
    print(f"normal")


print(name_value)

# Printing the result
# print("Name:", name_value)


