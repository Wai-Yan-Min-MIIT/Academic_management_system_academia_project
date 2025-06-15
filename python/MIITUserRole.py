import pandas as pd

df = pd.read_excel('SampleData3.xlsx', sheet_name='MIITUsers')

data = []

for index, row in df.iterrows():
    user_id = row['UserID'].upper()
    role_ids = row['RoleID'].split(',')
    
    for role_id in role_ids:
        data.append([user_id, role_id.strip()])
        
df = pd.DataFrame(data, columns=['UserID', 'RoleID'])

with pd.ExcelWriter('data.xlsx', mode='a', engine='openpyxl') as writer:
    df.to_excel(writer, sheet_name='MIITUserRole', index=False)
  
print("MIITUserRole data generated in data.xlsx")
