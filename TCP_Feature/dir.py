import pyshark

cap = pyshark.FileCapture(
    "test_pcap/TCP Test 5.pcap",
    display_filter="ip.addr == 64.29.17.131",
)



# obtain all the field names within the ETH packets

for attr in dir(cap[0].tcp):
    print(attr)
# field_names = packet.icmp._all_fields

# # obtain all the field values
# field_values = packet.icmp._all_fields.values()

# # enumerate the field names and field values
# for field_name, field_value in zip(field_names, field_values):
#     print(f"{field_name}:  {field_value}")

cap.close()
