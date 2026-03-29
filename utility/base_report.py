from abc import ABC, abstractmethod
import pymongo
import inspect
import os
import json
 
class Element:
    def __init__(self, type):
            self.type = type
     
class GraphElement(Element):
    def __init__(self, xdata=0, ydata=0, xlabel="", ylabel="", title="", chart_type="", callable_func=None):
        """xdata=0, ydata=0, xlable="", ylabel="", title="""
        super().__init__("Graph")
        
        self.xdata = xdata
        self.ydata = ydata
        self.xlabel = xlabel
        self.ylabel = ylabel
        self.title = title
        self.chart_type = "line"
        self.func = callable_func
        
    def get_content(self):
        if callable(self.func):
            self.xdata, self.ydata, self.xlabel, self.ylabel = self.func()
            return self.get_chartjs_config()
        else:
            return self.get_chartjs_config()
    
        
    def get_chartjs_config(self):
        return {
            "type": self.chart_type,
            "data": {
                "labels": self.xdata,
                "datasets": [{
                    "label": self.ylabel, # ชื่อชุดข้อมูล (Legend)
                    "data": self.ydata,
                    "borderColor": "rgba(75, 192, 192, 1)",
                    "tension": 0.3
                }]
            },
            "options": {
                "responsive": True,
                "scales": {
                    "x": {
                        "display": True,
                        "title": {
                            "display": True,
                            "text": self.xlabel, # Label แกน X
                            "font": {"size": 14, "weight": "bold"}
                        }
                    },
                    "y": {
                        "display": True,
                        "title": {
                            "display": True,
                            "text": self.ylabel, # Label แกน Y
                            "font": {"size": 14, "weight": "bold"}
                        },
                        "beginAtZero": True # ให้แกน Y เริ่มที่ 0 เสมอ
                    }
                }
            }
        }


class TableElement(Element):
    def __init__(self, tabledata=[], title="", callable_func=None):
        super().__init__("Table")
        self.tabledata = tabledata
        self.title = title
        self.func = callable_func
            
    def get_content(self):
        if callable(self.func):
            return self.func()
        else:
            return self.tabledata

class ParagraphElement(Element):
    def __init__(self, text="", title="", callable_func=None):
        super().__init__("Paragraph")
        self.text = text
        self.title = title
        self.func = callable_func
        
    def get_content(self):
        if callable(self.func):
            return self.func()
        else:
            return self.text
        
        
class Block:
    def __init__(self):
        self.elements = []
    
    def add_element(self, element: Element):
        self.elements.append(element)
        return self 

    def get_all_elements(self):
        return self.elements

class Dashboard:
    def __init__(self):
        self.blocks = []
        self.header = ""
        
    def add_block(self, block):
        self.blocks.append(block)
    
    def create_dashboard_json(self):
        blueprint = {}
        for i, block in enumerate(self.blocks):
            # check ว่า block มี elements มั้ย
            block_id = f"block_{i}"
            blueprint[block_id] = {}
            for y, element in enumerate(block.get_all_elements()):
                element_id = f"element_{y}"
                blueprint[block_id][element_id] = {"type" : element.type,
                                                   "title" : element.title}
                
                blueprint[block_id][element_id]["content"] = element.get_content()
                blueprint[block_id][element_id]["html_id"] = f"b{i}e{y}"


        return json.dumps(blueprint, indent=4)



class BaseDashboardGenerator(ABC):
        
    def __init__(self,collection : pymongo.collection, target_ip, ports, report_name="", output_path=""):
        self.result_collection = collection
        self.target_ip = target_ip
        self.ports = ports
        full_path = inspect.getfile(self.__class__)
        folder_path = os.path.dirname(full_path)
        folder_name = os.path.basename(folder_path)
        
        self.dashboard = Dashboard()
        
        self.report_name = f"{folder_name}_report.pdf"
        self.output_path = f"result/{folder_name}"
        if not report_name == "":
            self.report_name = report_name
        if not output_path == "":
            self.output_path = output_path
            
        # check ว่ามี output path มั้ยถ้าไม่มีให้สร้าง
        os.makedirs(self.output_path, exist_ok=True)
        self.output_file = f"{self.output_path}/{self.report_name}"
        
    @abstractmethod    
    def generate_dashboard():
        pass
    
    def create_block(self):
        block = Block()    
        self.dashboard.add_block(block)
        return block
    
    def set_report_name(self, report_name):
        self.report_name = report_name
    
    def set_dashboard_header(self,header : str):
        self.dashboard.header = header
    
    # def create_graph_element(xdata, ydata, xlabel, ylabel, title):
    #     graph = GraphElement(xdata, ydata, xlabel, ylabel, title)
    #     return graph
    
    # def create_paragraph_element(text):
    #     paragraph = ParagraphElement(text=text)
    #     return paragraph
        
    # def create_table_element(tabledata):
    #     tabledata = TableElement(tabledata=tabledata)
    #     return tabledata