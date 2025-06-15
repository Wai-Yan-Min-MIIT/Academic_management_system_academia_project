import datetime
import pandas as pd

data = []

start_year = 2014
end_year = 2023

for year in range(start_year, end_year+1):

  start_date = datetime.date(year, 1, 1)
  end_date = datetime.date(year+1, 1, 1)
  
  ay_id = f"AY{str(year-2013).zfill(2)}"
  
  data.append([ay_id, start_date, end_date, start_date])
  
df = pd.DataFrame(data, columns=['AY_ID', 'AYStartDate', 'AYEndDate', 'AYCreateDate'])

with pd.ExcelWriter('data.xlsx', engine='openpyxl', mode='a') as writer:
  df.to_excel(writer, sheet_name='AcademicYear Data', index=False)
  
print("AcademicYear Data sheet generated successfully in the data.xlsx file!")
