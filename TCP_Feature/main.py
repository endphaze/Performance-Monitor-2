from gns3fy import Gns3Connector

# เชื่อมต่อกับ GNS3 Server
server = Gns3Connector("http://localhost:3080")

# แสดงโปรเจกต์ทั้งหมด
projects = server.get_projects()
for project in projects:
    print(f"Project Name: {project['name']}, ID: {project['project_id']}")
