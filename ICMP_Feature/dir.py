import pyshark

cap = pyshark.FileCapture(
    "test_pcap/ICMP Test 2.pcap",
    display_filter="ip.addr == 192.168.182.150 and icmp.resptime",
)


packet = cap[0]
# obtain all the field names within the ETH packets

for attr in dir(cap[0].icmp.type):
    print(attr)
# field_names = packet.icmp._all_fields

# # obtain all the field values
# field_values = packet.icmp._all_fields.values()

# # enumerate the field names and field values
# for field_name, field_value in zip(field_names, field_values):
#     print(f"{field_name}:  {field_value}")

cap.close()
