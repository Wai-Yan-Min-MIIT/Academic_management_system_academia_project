import pandas as pd

df1 = pd.read_excel('SampleData2.xlsx', sheet_name='Student')
df2 = pd.read_excel('SampleData2.xlsx', sheet_name='Faculty')
df3 = pd.read_excel('SampleData3.xlsx', sheet_name='MIITUsers')

data = []

for index, row in df3.iterrows():

    user_id = row['UserID'].upper()
    password = row['UserPasswordKey']
    email = None
    
    if user_id in df1['UserID'].values:
        email = df1.loc[df1['UserID'] == user_id, 'RollNumber'].values[0].lower() + '@miit.edu.mm'

    elif user_id in df2['UserID'].values:  
        email = df2.loc[df2['UserID'] == user_id, 'FacultyStaffID'].values[0].lower() + '@miit.edu.mm'
    if email:
        data.append([user_id, email, password, 'active'])
  
df = pd.DataFrame(data, columns=['UserID', 'Email', 'UserPasswordKey', 'UserStatus'])

with pd.ExcelWriter('data.xlsx', engine='openpyxl', mode='a') as writer:
  df.to_excel(writer, sheet_name='MIITUsers Data', index=False)

print("MIITUsers data generated successfully!")
