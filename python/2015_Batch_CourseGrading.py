import pandas as pd

sheet1 = pd.read_excel('2015.xlsx', sheet_name='Sheet1')
grades = pd.read_excel('data.xlsx', sheet_name='GradePoint Data')
semester_grading = pd.read_excel('data_1.xlsx', sheet_name='SemesterGrading')

grade_map = {r.Grade: r['GradePointID'] for _, r in grades.iterrows()}

course_grading = sheet1[['ID','CourseCode','Grade']]
course_grading['GradePointID'] = course_grading['Grade'].map(grade_map)

# We map the ID column from Sheet1 to the SemesterGradingIDs from the SemesterGrading sheet.
sheet1_ids = sheet1['ID']
semester_ids = semester_grading['SemesterGradingID']

id_to_sem = dict(zip(sheet1_ids, semester_ids))
course_grading['SemesterGradingID'] = course_grading['ID'].map(id_to_sem)

# =====================

course_grading = course_grading[['SemesterGradingID','CourseCode','GradePointID']]

with pd.ExcelWriter('data_1.xlsx', engine='openpyxl', mode='a') as writer:
    course_grading.to_excel(writer, sheet_name='CourseGrading', index=False)

print("CourseGrading sheet generated")