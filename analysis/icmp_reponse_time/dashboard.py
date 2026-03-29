from utility.base_report import BaseDashboardGenerator, GraphElement, TableElement, ParagraphElement
import matplotlib.pyplot as plt
import pandas as pd
import os




class DashboardGenerator(BaseDashboardGenerator):
    
    
    # def rtt_graph(self):
    #     self.result_collection.find()
    #     return 
    
    # def info_paragraph(self):
    #     return "paragraph"
    
    # def table_minmaxavrg(self):
    #     min = 0
    #     max = 0
    #     averaged = 0
        
    #     cursor = self.result_collection.find()
    #     for result in cursor
        
        
    def graph1_rtt(self):
        
        xlabel = "timestamp"
        ylabel = "rtt"
        xdata = []
        ydata = []
        pipeline = [
                    {
                        "$group": {
                            "_id": {
                                "timestamp": "$timestamp",  # จับกลุ่มตามวินาที
                            },
                            "avg_rtt": { 
                                "$avg": { "$toDouble": "$rtt" } # แปลง string เป็นตัวเลขแล้วหาค่าเฉลี่ย
                            },
                            "count": { "$sum": 1 } # นับจำนวน packet ในวินาทีนั้นๆ
                        }
                    },
                    {
                        "$sort": { "_id.timestamp": 1 } # เรียงลำดับตามเวลาจากน้อยไปมาก
                    }
                ]
            
        for cursor in self.result_collection.find():
            print(cursor)
        
        return xdata, ydata, xlabel, ylabel    
    
        


    
    def generate_dashboard(self):
        block1 = self.create_block()
        paragraph1 = ParagraphElement(title="Testing", text="Hello World")
        graph1 = GraphElement(callable_func=self.graph1_rtt, title="Average Response Time (ms)")
        
        
        block1.add_element(graph1)
        block1.add_element(paragraph1)

        
            
        