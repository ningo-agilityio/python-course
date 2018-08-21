# Pull from hub.docker.com the image python3
FROM python:3

# Inside the machine Ubuntu, we choose folder to work with
WORKDIR /usr/src/app

# Copy file requirements.txt to install python libs, dependencies
COPY requirements.txt .

# Tell machine to run pip insteall
RUN pip install --no-cache-dir -r requirements.txt

# Copy file in current folder to folder of current machine
COPY . .

RUN pip install ./en_core_web_sm-2.0.0.tar.gz

# Run app with python
CMD ["python", "app.py"]