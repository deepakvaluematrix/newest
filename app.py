from flask import Flask, request, jsonify
from threading import Thread, Event
import time
import base64
import cv2
from flask_jwt_extended import JWTManager
from flask_cors import CORS
import os
import pymongo
import requests
import numpy as np
from utils.EarpieceDetection import EarpieceDetection

app = Flask(__name__)
jwt = JWTManager(app)
CORS(app)

# Global dictionary to store session events
session_events = {}

CWD = os.getcwd()
ear_model_file_path = os.path.join(CWD, "models", "EarPlug3.onnx")
ear_d = EarpieceDetection(ear_model_file_path=ear_model_file_path)

global session_dictionary
session_dictionary = {}

client = pymongo.MongoClient("mongodb+srv://manas:mAN123%40pap@cluster-ma.9w89o6i.mongodb.net/?retryWrites=true&w=majority")
db = client["DataScience"]

def readb64(uri):
    encoded_data = uri
    nparr = np.frombuffer(base64.b64decode(encoded_data), np.uint8)
    img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    return img

def is_valid_request(body_job_id, body_link):
    if body_job_id != "" and body_link != "":
        return True
    return False

class CustomThread(Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs={}, Verbose=None):
        Thread.__init__(self, group, target, name, args, kwargs)
        self.returnValue = None

    def run(self):
        if self._target is not None:
            self.returnValue = self._target(*self._args, **self._kwargs) 

    def join(self):
        Thread.join(self)
        return self.returnValue

def verifytoken(token):
    interservive_url = os.getenv('INTERSERVICE_URL')
    verify_token_url = interservive_url + '/token/verify_token'
    headers = {'Authorization': f'Bearer {token}'}

    response = requests.post(verify_token_url, headers=headers)
    return response

# API for ear detection
@app.route('/baselining', methods=['POST'])
def heimdall_baselining_ear():
    try:
        authorization_header = request.headers.get('Authorization')
        if authorization_header:
            token = request.headers.get('Authorization').split()[1]
            response = verifytoken(token)
            if response.status_code == 200:
                input = request.get_json()
                img = readb64(input['img'])
                ear_d = EarpieceDetection(ear_model_file_path=ear_model_file_path)
                img, data = ear_d.run_ear_img(img)
                base64_img = base64.b64encode(img).decode()
                return jsonify({"data": data, "img": base64_img})
            elif response.status_code == 401:
                return jsonify({'message': 'Token is expired'}), 403
            else:
                return jsonify({'message': 'Token is invalid'}), 401
        else:
            return jsonify({'message': 'Authorization header is missing or empty'}), 401
    
    except Exception as e:
        raise e
    
def start_processing(job_id, body_link):
    try:
        global db
        global exit_event
        exit_event = Event()
        global session_exit_event
        coll = db["InterviewAnalysis"]
        session_dictionary[f"Batch:{job_id}"] = coll.count_documents({"MeetingId": f"{job_id}", "EarpieceDetection": {"$exists": "true"}})

        def parallel_threads_starting():
            global thread1
            global exit_event
            session_Dictionary = session_dictionary[f"Batch:{job_id}"] + 1
            thread1 = CustomThread(target=ear_d.run, args=(job_id, body_link, exit_event, coll, session_Dictionary), name='EarpieceDetection')
            thread1.start()

        def parallel_threads_joining()->dict:
            global exit_event
            global thread1
            data={}
            exit_event.set()
            data[f'{thread1.name}']=thread1.join()
            exit_event=Event()    
            return data

        t1 = time.perf_counter()
        parallel_threads_starting()
        while True:
            t2=time.perf_counter()
            if int(t2-t1)==60:
                d=parallel_threads_joining()
                d['time']=60
                session_dictionary[f"Batch:{job_id}"]+=1
                d['Batch_Id']=session_dictionary[f"Batch:{job_id}"]
                #string=str(d)
                d["MeetingId"]=job_id
                coll.insert_one(d)  #for mongo db
                parallel_threads_starting()
                t1=t2
            else:
                pass 
            if session_dictionary[f"{job_id}"].is_set():
                d=parallel_threads_joining()
                d['time']=float(t2-t1)
                session_dictionary[f"Batch:{job_id}"]+=1
                d['Batch_Id']=session_dictionary[f"Batch:{job_id}"]
                d["MeetingId"]=job_id
                coll.insert_one(d)
                break

    except Exception as e:
        raise e

@app.route('/proctoring/earpiecedetection/<string:job_id>/start', methods=['POST'])
def starttask(job_id):
    try:
        authorization_header = request.headers.get('Authorization')
        if authorization_header:
            token = request.headers.get('Authorization').split()[1]
            response = verifytoken(token)

            if response.status_code == 200:
                global session_dictionary
                session_dictionary[f"{job_id}"] = Event()
                body_link = request.json.get("link")

                if is_valid_request(job_id, body_link) == False:
                    return "Bad request, invalid job_id: %s or operator: %s" % (job_id, body_link), 401
                
                # Start processing in the background
                processing_thread = Thread(target=start_processing, args=(job_id, body_link))
                processing_thread.start()

                return jsonify({'Status': f'{job_id} started'})

            elif response.status_code == 401:
                return jsonify({'message': 'Token is expired'}), 403
            else:
                return jsonify({'message': 'Token is invalid'}), 401

        else:
            return jsonify({'message': 'Authorization header is missing or empty'}), 401

    except Exception as e:
        raise e

@app.route('/proctoring/earpiecedetection/<string:job_id>/stop', methods=['POST'])
def stoptask(job_id):
    try:
        authorization_header = request.headers.get('Authorization')
        if authorization_header:
            token = request.headers.get('Authorization').split()[1]
            response = verifytoken(token)

            if response.status_code == 200:
                global session_dictionary
                session_dictionary[f"{job_id}"].set()
                return jsonify(f"{job_id} stopped")
            elif response.status_code == 401:
                return jsonify({'message': 'Token is expired'}), 403
            else:
                return jsonify({'message': 'Token is invalid'}), 401

        else:
            return jsonify({'message': 'Authorization header is missing or empty'}), 401

    except Exception as e:
        raise e

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, threaded=True, port=8028)



