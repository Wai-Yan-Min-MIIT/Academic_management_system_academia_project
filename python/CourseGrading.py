import pandas as pd

grades_df = pd.read_excel('SampleData3.xlsx', sheet_name='StudentGrade')
students_df = pd.read_excel('data.xlsx', sheet_name='Student')
sem_grade_df = pd.read_excel('data.xlsx', sheet_name='SemesterGrading Data')
gradepoints_df = pd.read_excel('data.xlsx', sheet_name='GradePoint Data')

course_grading = []

for index, grade_row in grades_df.iterrows():
    roll_num = grade_row['RollNumber']
    semester_num = grade_row['SemesterNumber']
    semester_id = grade_row['SemesterID']

    course_code = grade_row['CourseCode']
    course_grade = grade_row['Grade']  

    filter_df = gradepoints_df[gradepoints_df['Grade'] == course_grade]
    
    if len(filter_df) > 0:
        grade_row = filter_df.iloc[0]
        gradepoint_id = grade_row['GradePointID']
    
    else:
        print(f"No gradepoint found for {course_grade}")
        gradepoint_id = None

    student_row = students_df[students_df['RollNumber'] == roll_num].iloc[0]
    student_id = student_row['StudentID']

    sem_grade_row = sem_grade_df[(sem_grade_df['StudentID'] == student_id) &
                                (sem_grade_df['SemesterNumber'] == semester_num) &
                                (sem_grade_df['SemesterID'] == semester_id)].iloc[0]
    sem_grading_id = sem_grade_row['SemesterGradingID']
                                
    course_grading.append([
        sem_grading_id, 
        course_code,
        gradepoint_id
    ])
  
course_grading_df = pd.DataFrame(course_grading, columns=[
  'SemesterGradingID', 'CourseCode', 'GradePointID'  
])

with pd.ExcelWriter('data.xlsx', mode='a', engine='openpyxl') as writer:
  course_grading_df.to_excel(writer, sheet_name='CourseGrading', index=False)

print('Course Grading data generated!')
