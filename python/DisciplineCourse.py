import pandas as pd

df = pd.read_excel('SampleData.xlsx', sheet_name='Basechart')

data = [] 

for index, row in df.iterrows():

  course_code = row['CourseNumber']  

  if "ELECTIVE" not in course_code:

    discipline_id = row['DisciplineCode']
    
    data.append([discipline_id, course_code])

df = pd.DataFrame(data, columns=['DisciplineID', 'CourseCode']) 

with pd.ExcelWriter('data.xlsx', engine='openpyxl', mode='a') as writer:
  df.to_excel(writer, sheet_name='DisciplineCourse Data', index=False)
  
print("DisciplineCourse Data sheet generated successfully!")