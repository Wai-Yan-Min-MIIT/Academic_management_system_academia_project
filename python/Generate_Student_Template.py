from openpyxl import Workbook

def generate_student_data_excel():
    # Create a new Workbook
    wb = Workbook()
    ws = wb.active
    
    # Define column headers
    headers = ['Student Name', 'Salutation', 'Discipline', 'Program', 'Batch Year', 'Section', 
               'Roll Number', 'Student NRC', 'Student Phone', 'Student DOB', 'ACB Status', 
               'Guardian Name', 'Guardian NRC', 'Guardian Phone', 'Address']

    # Write headers to the first row
    for col, header in enumerate(headers, start=1):
        ws.cell(row=1, column=col, value=header)

    # Save the workbook
    wb.save('Student_Data.xlsx')
    
    print("Student_Data.xlsx created successfully.")

if __name__ == "__main__":
    generate_student_data_excel()
