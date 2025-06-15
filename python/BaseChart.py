import pandas as pd
import openpyxl
from datetime import datetime

# Read the PBD data from the PBDData sheet in data.xlsx file
df_pbd = pd.read_excel('data.xlsx', sheet_name='ProgramBatchDiscipline Data')

# Create a new workbook
wb = openpyxl.load_workbook('data.xlsx')

# Create a worksheet for the BaseChart data
ws_basechart = wb.create_sheet('BaseChart')

# Set the header row for the BaseChart worksheet
ws_basechart.append(['BaseChartID', 'PBD_ID', 'CreatedDate', 'ModifiedDate'])

# Generate BaseChartID for each PBD_ID
basechart_id = 'BC001'
for index, row in df_pbd.iterrows():
    ws_basechart.append([basechart_id, row['PBD ID'], datetime.now(), datetime.now()])
    basechart_id = 'BC' + str(int(basechart_id[2:]) + 1).zfill(3)

print("Successfully created BaseChart")
wb.save('data.xlsx')
