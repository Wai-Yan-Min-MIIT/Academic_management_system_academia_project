import pandas as pd

# Read Sheet1 data
df = pd.read_excel('2015.xlsx', sheet_name='Sheet1')

# Read Student data
students = pd.read_excel('data.xlsx', sheet_name='Student')

# Map StudentRollNumbers to StudentIDs
roll_to_id = {r: i for r, i in zip(students['RollNumber'], students['StudentID'])}

# Add StudentIDs
df['StudentID'] = df['StudentRollNumber'].map(roll_to_id)

# Add Semester Grading IDs
df['SemesterGradingID'] = 'SG' + df.index.astype(str).str.zfill(5)

# # Create custom range of SemesterGradingIDs starting from 'SG00077'
# start_id = 77
# df['SemesterGradingID'] = ['SG' + str(i).zfill(5) for i in range(start_id, start_id + len(df))]


# Filter columns
semester_grading = df[['SemesterGradingID', 'StudentID',
                       'SemesterID', 'SemesterNumber']]

# Set Deleted to 0
semester_grading['Deleted'] = 0


# # Use .loc to set values without the warning
# semester_grading.loc[:, 'Deleted'] = 0


# # Write to Excel
semester_grading.to_excel('data_1.xlsx', sheet_name='SemesterGrading', index=False)

print("SemesterGrading sheet generated")



