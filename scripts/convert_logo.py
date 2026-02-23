from PIL import Image
import os

def convert_to_ico(input_path, output_path):
    img = Image.open(input_path)
    # Define standard icon sizes
    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    img.save(output_path, format='ICO', sizes=sizes)
    print(f"Successfully converted {input_path} to {output_path}")

if __name__ == "__main__":
    input_logo = r"c:\Users\rayki\OneDrive\Desktop\Empire\Ideas\Raypher .exe\raypher-phase1-complete-master\Raypher.logo.png"
    output_ico = r"c:\Users\rayki\OneDrive\Desktop\Empire\Ideas\Raypher .exe\raypher-phase1-complete-master\assets\raypher_logo.ico"
    
    if not os.path.exists(os.path.dirname(output_ico)):
        os.makedirs(os.path.dirname(output_ico))
        
    convert_to_ico(input_logo, output_ico)
