import pandas as pd
from datetime import date

df = pd.read_excel('SampleData3.xlsx', sheet_name='Semester')

data = []

for index, row in df.iterrows():

  semester_id = row['SemesterNumber']  
  program_id = row['ProgramCode']
  ay_id = row['AYCode']
  start_date = date(2020, 1, 1)  
  end_date = date(2020, 6, 30)
  
  data.append([
    semester_id,  
    ay_id,
    program_id,
    row['SemesterStatus'],
    start_date,
    end_date,
    ''
  ])
  
df = pd.DataFrame(data, columns=[
  'SemesterID', 'AY_ID', 'ProgramID', 
  'SemesterStatus', 'SemesterStartDate', 
  'SemesterEndDate', 'SemesterDescription'
])

with pd.ExcelWriter('data.xlsx', engine='openpyxl', mode='a') as writer:
  df.to_excel(writer, sheet_name='Semester', index=False)

print("Semester data generated!")
