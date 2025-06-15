import pandas as pd

# Read project data
projects_df = pd.read_excel('SampleData3.xlsx', sheet_name='OfferedProjects') 

# Rename columns
projects_df.rename(columns={
  'SemesterNumber': 'SemesterID',
  'ProjectNumber': 'ProjectCode'   
}, inplace=True)

# Set ProjectCredits based on ProjectType
projects_df['ProjectCredits'] = projects_df.apply(lambda x: 3 if x['ProjectType']==1 else 20, axis=1)

# Reorder columns
projects_df = projects_df[[
  'ProjectCode', 'FacultyStaffID', 'SemesterID', 'ProjectTitle', 'ProjectCredits',
  'NumbStudents', 'ProjectSummary', 'Deleted', 'ProjectType', 'Remarks'  
]]

# Write to new sheet in data.xlsx
with pd.ExcelWriter('data.xlsx', mode='a', engine='openpyxl') as writer:
  projects_df.to_excel(writer, sheet_name='Project Data', index=False)

print('Project data generated!')