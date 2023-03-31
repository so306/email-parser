from __future__ import print_function

import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

import pprint
import base64
import email

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

senders = []


def main():
    """Lists user's Gmail labels."""
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        # all_labels = service.users().labels().list(userId='me').execute()
        # labels = results.get('labels', [])
        
        # what is users()

        unread_msgs = service.users().messages().list(userId='me',labelIds=['INBOX', 'UNREAD']).execute()
        pp = pprint.PrettyPrinter(indent=4)
        threadids_unread_msgs = [msg['threadId'] for msg in unread_msgs['messages']]
        # pp.pprint(threadids_unread_msgs)
        # message_bodies = [service.users().messages().get(userId='me', id=id).execute() for id in threadids_unread_msgs]

        for id in threadids_unread_msgs:
            message_list_full = service.users().messages().get(userId='me', id=id, format='full').execute()
            # print(id)
        
            payload = message_list_full['payload']

            message_headers = payload['headers']

            for header in message_headers:
                if header['name'] == 'From':
                    senders.append(header['value'])

        print(senders)


        message_list_raw = service.users().messages().get(userId='me', id=threadids_unread_msgs[1], format='raw').execute()
        msg_raw = base64.urlsafe_b64decode(message_list_raw['raw'].encode('ASCII'))
        msg_str = email.message_from_bytes(msg_raw)

        """
        # content_types = msg_str.get_content_maintype()

        # print(msg_str)
        """
        
        # payload = trial_msg['payload']
        # headers = payload.get("headers")
        # parts = payload.get("parts")
        # folder_name = "email"
        # print(payload)

        # messages = unread_msgs.get('messages', []) #idk what tis does

        # message_bodies = [service.users().messages().get(userId='me', id=msg['id']).execute() for msg in messages]
        # print("hi",message_bodies[0])
        # for msg in message_bodies:
        #     print(msg)


        # all_msgs = service.users().messages().list(userId='me').execute()
        # # print(unread_msgs['messages']) what is this even getting
        # arr = [msg for msg in unread_msgs: if msg['id'] in ]
        # print(arr[0]["raw"])



        # all_messages = service.users().messages().list(userId='me').execute()
        # print(all_messages)
        # unread_messages = [msg for msg in all_messages.labelIds
        #         if msg == "UNREAD"]
        # print(unread_messages)

        # if not labels:
        #     print('No labels found.')
        #     return
        # print('Labels:')
        # for label in labels:
        #     print(label['name'])

    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')


if __name__ == '__main__':
    main()