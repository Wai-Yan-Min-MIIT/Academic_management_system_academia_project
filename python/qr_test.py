import qrcode
from PIL import Image, ImageDraw

def generate_qr_with_logo_and_frame(data, logo_path, output_path):
    # Generate QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white")

    # Create a white circle frame
    circle_radius = 40
    frame_width = 5
    frame_color = "white"
    circle_center = ((qr_img.size[0] - 1) // 2, (qr_img.size[1] - 1) // 2)
    frame_box = (
        circle_center[0] - circle_radius - frame_width,
        circle_center[1] - circle_radius - frame_width,
        circle_center[0] + circle_radius + frame_width,
        circle_center[1] + circle_radius + frame_width,
    )
    frame_img = Image.new("RGBA", qr_img.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(frame_img)
    draw.ellipse(frame_box, fill=frame_color)

    # Paste frame on QR code
    qr_img = Image.alpha_composite(qr_img.convert("RGBA"), frame_img)

    # Load logo
    logo = Image.open(logo_path)
    logo = logo.convert("RGBA")  # Ensure logo is RGBA format
    logo = logo.resize((circle_radius * 2, circle_radius * 2), Image.LANCZOS)

    # Calculate position for the logo
    position = (
        circle_center[0] - circle_radius,
        circle_center[1] - circle_radius,
    )

    # Paste logo on QR code
    qr_img.paste(logo, position, logo)

    # Save QR code with logo and frame
    qr_img.save(output_path)

if __name__ == "__main__":
    data = "Your QR code data here"
    logo_path = "D:/SEMESTER-VIII/Special Project/project_academia/static/images/miit-logo.png"
    output_path = "qr_with_logo_and_frame.png"
    generate_qr_with_logo_and_frame(data, logo_path, output_path)
