



# Table 5 : Top Ports
data_ports = [['Port', 'Requests Count']]
for port, frequency in top_ports:
    data_ports.append([port, frequency])

t5 = Table(data_ports)
elements.append(Paragraph("Top Ports", styles['Heading2']))
elements.append(t5)
elements.append(Spacer(1, 12))

elements.append(Paragraph("Top Ports", styles['Heading2']))