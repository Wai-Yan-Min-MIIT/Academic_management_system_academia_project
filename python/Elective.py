import pandas as pd

# Read course table from Course Data sheet
courses = pd.read_excel('data.xlsx', sheet_name='Course Data')
course_codes = courses['CourseCode'].tolist()

# Read and filter DisciplineCourse
df = pd.read_excel('SampleData3.xlsx', sheet_name='DisciplineCourse')
electives = df[df['CourseType'] == 'Elective']
filtered = electives[electives['CourseNumber'].isin(course_codes)]

# Add new column "Deleted" with default value 0
filtered['Deleted'] = 0

# Generate elective codes
elective_codes = ['EC%04d' % (i+1) for i in range(len(filtered))]
filtered['ElectiveCourseCode'] = elective_codes

columns = ['ElectiveCourseCode', 'CourseNumber', 'Deleted']
with pd.ExcelWriter('data.xlsx', mode='a', engine='openpyxl') as writer:
    filtered[columns].to_excel(writer, sheet_name='Elective Courses Data', index=False)

print("Elective courses data generated successfully")
