import pandas as pd

df1 = pd.read_excel('SampleData.xlsx', sheet_name='Basechart')  
df2 = pd.read_excel('data.xlsx', sheet_name='Batch Data')
df3 = pd.read_excel('data.xlsx', sheet_name='ProgramBatchDiscipline Data')
df4 = pd.read_excel('data.xlsx', sheet_name='BaseChart')

pbd_ids = []
basechart_ids = []

batch_mapping = {
    "2015": {
        "S1": 1, "S2": 1, "S3": 1, 
        "S4": 2, "S5": 2, "S6": 2,
        "S7": 3, "S8": 3, "S9": 3,
        "S10": 4, "S11": 4, "S12": 4,
        "S13": 5, "S14": 5, "S15": 5
    },
    "2016": {
        "S1": 1, "S2": 1, "S3": 1, 
        "S4": 2, "S5": 2, "S6": 2,
        "S7": 3, "S8": 3, "S9": 3,
        "S10": 4, "S11": 4, "S12": 4,
        "S13": 5, "S14": 5
    },
    "2017": {
        "S1": 1, "S2": 1, "S3": 1, 
        "S4": 2, "S5": 2, "S6": 2,
        "S7": 3, "S8": 3, "S9": 3,
        "S10": 4, "S11": 4,
        "S12": 5, "S13": 5
    },
    "2018": {
        "S1": 1, "S2": 1, "S3": 1, 
        "S4": 2, "S5": 2, "S6": 2,
        "S7": 3, "S8": 3,
        "S9": 4, "S10": 4,
        "S11": 5, "S12": 5
    },
    "2019": {
        "S1": 1, "S2": 1, "S3": 1, 
        "S4": 2, "S5": 2,
        "S6": 3, "S7": 3,
        "S8": 4, "S9": 4,
        "S10": 5, "S11": 5
    },
    "2021": {
        "S1": 1, "S2": 1,
        "S3": 2, "S4": 2,
        "S5": 3, "S6": 3,
        "S7": 4, "S8": 4,
        "S9": 5, "S10": 5
    },
    "2022": {
        "S1": 1, "S2": 1,
        "S3": 2, "S4": 2,
        "S5": 3, "S6": 3,
        "S7": 4, "S8": 4,
        "S9": 5, "S10": 5
    },
    "2023": {
        "S1": 1, "S2": 1,
        "S3": 2, "S4": 2,
        "S5": 3, "S6": 3,
        "S7": 4, "S8": 4,
        "S9": 5, "S10": 5
    }
}

for index, row in df1.iterrows():

    discipline_code = row['DisciplineCode']
    course_number = row['CourseNumber']
    
    if discipline_code == 'D01':
        program_id = 'P01' 
    else:
        program_id = 'P02'

    batch_year = row['Batch']
    
    batch_id = df2.loc[df2['Batch Year'] == batch_year, 'Batch ID'].values[0]

    try:
        pbd_id = df3.loc[(df3['Program ID'] == program_id) & 
                         (df3['Batch ID'] == batch_id) &
                         (df3['Discipline ID'] == discipline_code),
                        'PBD ID'].values[0]
                        
        pbd_ids.append(pbd_id)
        
    except IndexError:
        print("No PBD ID match")

basechart_ids = []

for pbd_id in pbd_ids:
    basechart_id = df4.loc[df4['PBD_ID'] == pbd_id, 'BaseChartID'].values[0]
    basechart_ids.append(basechart_id)
   
data = []

for i in range(len(basechart_ids)):
    basechart_id = basechart_ids[i]
    course_code = df1.loc[i, 'CourseNumber']
    semester_number = df1.loc[i, 'SemesterNumber']
    
    batch_year = df1.loc[i, 'Batch']

    if basechart_id == 'BC001':
       year_number = 1
    
    else:
        year_number = batch_mapping[str(batch_year)][semester_number]

    data.append([basechart_id, course_code, year_number, semester_number])

    print(f"{i + 1} rows generated!")
   
df = pd.DataFrame(data, columns=['BaseChartID', 'CourseCode', 'YearNumber', 'SemesterNumber']) 

with pd.ExcelWriter('data.xlsx', engine='openpyxl', mode='a') as writer:  
   df.to_excel(writer, sheet_name='OfferedCourses_New', index=False)
   
print("OfferedCourses sheet generated in data.xlsx")
