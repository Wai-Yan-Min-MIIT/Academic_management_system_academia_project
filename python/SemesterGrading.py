import pandas as pd

# Load Excel files
grades_df = pd.read_excel('SampleData3.xlsx', sheet_name='StudentGrade')  
students_df = pd.read_excel('data.xlsx', sheet_name='Student')

# Initialize variables
grading_data = []
grading_id = 1 

# Track unique rows
unique_rows = set() 

# Loop through rows
for index, row in grades_df.iterrows():

    # Get Student ID
    roll_num = row['RollNumber']
    student_row = students_df[students_df['RollNumber'] == roll_num]

    if len(student_row) > 0:
        student_id = student_row['StudentID'].values[0]
    
    else:
        print(f'No student found for {roll_num}')
        continue

    # Create unique key
    unique_key = (student_id, row['SemesterID'], row['SemesterNumber'])

    # Check if already processed
    if unique_key in unique_rows:
        continue
    
    # Generate grading ID
    grading_id_str = 'SG' + str(grading_id).zfill(5)
    grading_id += 1

    # Add to grading data
    grading_data.append([
        grading_id_str, 
        student_id,
        row['SemesterID'],  
        row['SemesterNumber'],
        row['Deleted']
    ])

    # Mark key as processed
    unique_rows.add(unique_key)

# Create dataframe and write to Excel 
grading_df = pd.DataFrame(grading_data, columns=[
  'SemesterGradingID', 'StudentID', 'SemesterID',
  'SemesterNumber', 'Deleted'  
])

with pd.ExcelWriter('data.xlsx', mode='a', engine='openpyxl') as writer:
  grading_df.to_excel(writer, sheet_name='SemesterGrading Data', index=False)

print('Unique semester grading data generated!')
