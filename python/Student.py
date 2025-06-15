import pandas as pd

df1 = pd.read_excel('SampleData2.xlsx', sheet_name='Student')
df2 = pd.read_excel('data.xlsx', sheet_name='Batch Data')

data = []

for index, row in df1.iterrows():

  user_id = row['UserID']
  student_id = 'ST' + user_id

  discipline_code = row['DisciplineCode']
  if discipline_code == 'D01':
    program_id = 'P01'
  else:
    program_id = 'P02'

  roll_number = row['RollNumber']
  batch_year = roll_number.split('-')[0]
  batch_id = df2.loc[df2['Batch Year'] == int(batch_year), 'Batch ID'].values[0]

  data.append([
    student_id, user_id, discipline_code, program_id, batch_id,   
    row['StudentName'], row['Salutation'], row['StudentSection'],
    roll_number, row['StudentNRC'], row['StudentPhone'],  
    '', row['ACBStatus'],
    row['GuardianName'], row['GuardianNRC'], row['GuardianPhone'], row['Address']
  ])

df = pd.DataFrame(data, columns=[
  'StudentID', 'UserID', 'DisciplineID', 'ProgramID', 'BatchID',
  'StudentName', 'Salutation', 'SectionName', 'RollNumber', 
  'StudentNRC', 'StudentPhone', 'StudentDOB', 'ACBStatus',
  'GuardianName', 'GuardianNRC', 'GuardianPhone', 'Address'  
])
with pd.ExcelWriter('data.xlsx', mode='a', engine='openpyxl') as writer:
    df.to_excel(writer, sheet_name='Student', index=False)

print("Student data generated!")
