import PyInstaller.__main__
import os

# Get the absolute path of the script directory
script_dir = os.path.dirname(os.path.abspath(__file__))

PyInstaller.__main__.run([
    'v1.2.py',   # Add the good v1.x as you want
    '--name=Lakay Shelter',
    '--onefile',
    '--console',  # Console mode since it's a CLI application
    '--icon=shelter.ico',  # You'll need to create this icon
    f'--workpath={os.path.join(script_dir, "build")}',
    f'--distpath={os.path.join(script_dir, "dist")}',
    '--clean',
]) 
