import pandas as pd

df = pd.read_excel('SampleData3.xlsx', sheet_name='Role') 

data = []

for index, row in df.iterrows():
  role_id = row['RoleID']
  role_description = row['RoleDescription']
  
  data.append([role_id, role_description])

df = pd.DataFrame(data, columns=['RoleID', 'RoleDescription'])

with pd.ExcelWriter('data.xlsx', mode='a', engine='openpyxl') as writer:
  df.to_excel(writer, sheet_name='MIITRole', index=False)
  
print("MIITRole data generated successfully!")
