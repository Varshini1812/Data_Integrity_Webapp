# from django.shortcuts import render, redirect
# from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
# from .forms import CustomUserCreationForm  
# from django.core.mail import send_mail
# from .models import VerificationResult
# from django.contrib.auth import login, logout
# from django.contrib.auth.decorators import login_required
# import django.contrib.messages as messages
# from django.core.exceptions import ValidationError
# from django.http import HttpResponse
# import pandas as pd
# import numpy as np
# from pymongo.errors import ConnectionFailure
# from cloudsafeapp.mechanism import get_it_encrypted, get_it_decrypted
# from azure.cosmos import CosmosClient,exceptions,PartitionKey
# from random import randint
# import datetime
# import json
# import uuid
# from itertools import chain
# from io import StringIO
# import traceback
# from hashlib import sha256
# from cloudsafeapp.merkle1 import MerkleTree

# # ---- Home and Error
# URL = "https://host.documents.azure.com:443/"
# KEY = "UI9FKIjChuwBbJW8PkhCuAwGvoKyH6fgi1ZskAXpcBVCmfcidARvXZ6JRyWwBThUxaQ9DjFnTVnmACDbzqfdEw=="

# client = CosmosClient(URL,credential=KEY)

# DATABASE_NAME = 'DB'
# CONTAINER_NAME= "ITEMS"

# TPA_ID_PUBLICPARAMS = []




# def home_view(request):
#     return render(request, "home.html")


# def custom_404_view(request, exception):
#     print("[EXCEPTION] ", exception)
#     return render(request, "404.html", status=404)


# # ---- AUTHENTICATION AND AUTHORIZATION


# # def register_view(request):
  
# def register_view(request):
#     if request.method == "POST":
#         form = CustomUserCreationForm(request.POST)
#         if form.is_valid():
#             username = form.cleaned_data["username"]
           
#             try:
#                 # Assuming create_initial_collection is a custom function
#                 create_initial_collection(username)
#             except Exception as e:
#                 messages.error(
#                     request, f"Could not create a collection named {username}"
#                 )
#                 print("[EXCEPTION] ", e)
#                 return render(request, "register.html")
#             user = form.save()
#             login(request, user)
#             messages.success(
#                 request, f"Welcome {username}! You have successfully registered."
#             )
#             return redirect("dashboard")
#     else:
#         form =CustomUserCreationForm()
#     return render(request, "register.html", {"form": form})


# def login_view(request):
#     if request.method == "POST":
#         form = AuthenticationForm(request, data=request.POST)
#         if form.is_valid():
#             user = form.get_user()
#             login(request, user)
#             messages.success(
#                 request, f"Welcome {user.username}! You have successfully logged in."
#             )
#             return redirect("dashboard")
#     else:
#         form = AuthenticationForm()
#     messages_to_display = messages.get_messages(request)
#     return render(
#         request, "login.html", {"form": form, "messages": messages_to_display}
#     )


# def logout_view(request):
#     logout(request)
#     messages.success(request, "Successfully logged out.")
#     return redirect("login")  # Redirect to login page after logout


# # ---- DASHBOARD


# @login_required
# def dashboard_view(request):
#     messages_to_display = messages.get_messages(request)
#     return render(request, "dashboard.html", {"messages": messages_to_display})

# @login_required
# def delete_view(request, file_id):
#     if request.method == "POST":
#         try:
#             username = request.user.username
#             collection = get_collection(username)
#             # Retrieve the item based on file_id
#             items = collection.query_items(f'select * from c where c.id = "{file_id}"')
#             item = next(items)
#             # Delete the item
#             collection.delete_item(item, partition_key=file_id)
            
#             messages.success(request, "Successfully deleted the dataset.")
#             return redirect("dashboard")
#         except Exception as e:
           
#             messages.error(request, f"Failed to delete the dataset: {str(e)}")
#             return redirect("dashboard")
#     return redirect("fetch")

# # ---- FUNCTIONS
# @login_required
# # def activate_tpa_view(request):
# #     if request.method == "POST":
# #         username = request.user.username
# #         collection = get_collection(username)
       
# #         file_data = collection.query_items(
# #         f'SELECT * FROM container con WHERE con.username="{username}"',
# #         enable_cross_partition_query=True
# #         )
        
        
        
        
# #         encrypted_data = []
        
# #         stored_root = ""
        
# #         for item in file_data:
# #             if "data_with_blocks" in item:
# #                 data_blocks = item["data_with_blocks"]
# #             if "root_hash" in item:
# #                 stored_root = item["root_hash"]
        
# #         for item in data_blocks:
# #             if "data" in item:
# #                 encrypted_data.append(item["data"])

        

       

# #         df = pd.DataFrame(encrypted_data)
        
# #         # Instantiate Merkle tree
# #         merkle_tree = MerkleTree()
        
# #         # Build Merkle tree from DataFrame
# #         merkle_tree.makeTreeFromDataFrame(df)
        
# #         # Calculate Merkle root
# #         merkle_tree.calculateMerkleRoot()
        
# #         # Get calculated Merkle root
# #         calculated_root = merkle_tree.getMerkleRoot()
# #         print("claculated_root",calculated_root)
# #         print("stored_root",stored_root)
# #         res = ""
        
# #         if(stored_root == calculated_root):
# #             res = "Data verified Successfully and the data is unchanged"
           
# #             messages.success(request, res)
# #         else:
# #             res ="Data verified Successfully and the data have been tampered"
           
# #             messages.warning(request, res)
# #             # subject = "Data Integrity Alert"
# #             # message = f"Dear {username},\n\nYour data has been tampered with. Please check your account for more details."
# #             # recipient = request.user.email  # Assuming the User model has an email field
            
# #             # send_email(
# #             #     recipient,
# #             #     subject,
# #             #     message
# #             # )
        
# #         # Return a response
# #         return redirect("dashboard")


# @login_required
# def activate_tpa_view(request):
#     username = request.user.username
#     result = verify_data_integrity(username)
    
#     if result['status'] == 'tampered':
#         messages.warning(request, result['message'])
#     else:
#         messages.success(request, result['message'])

#     request.session['verification_result'] = result

#     return redirect("dashboard")

# def verify_data_integrity(username):
#     collection = get_collection(username)
#     file_data = collection.query_items(
#         f'SELECT * FROM container con WHERE con.username="{username}"',
#         enable_cross_partition_query=True
#     )

#     encrypted_data = []
#     stored_root = ""
    
#     for item in file_data:
#         if "data_with_blocks" in item:
#             data_blocks = item["data_with_blocks"]
#         if "root_hash" in item:
#             stored_root = item["root_hash"]

#     for item in data_blocks:
#         if "data" in item:
#             encrypted_data.append(item["data"])

#     df = pd.DataFrame(encrypted_data)
    
#     merkle_tree = MerkleTree()
#     merkle_tree.makeTreeFromDataFrame(df)
#     merkle_tree.calculateMerkleRoot()
#     calculated_root = merkle_tree.getMerkleRoot()
    
#     if stored_root == calculated_root:
#         return {'status': 'success', 'message': 'Data verified successfully and is unchanged.'}
#     else:
#         return {'status': 'tampered', 'message': 'Data verified successfully but has been tampered.'}

# def integrity_check_results(request):
#     results = VerificationResult.objects.all().order_by('-timestamp')
#     return render(request, 'verification_results.html', {'results': results})
     
# @login_required
# def upload_view(request):
#     if request.method == "POST" and request.FILES.get("file"):
#         uploaded_file = request.FILES["file"]
#         password = request.POST.get("password")
#         try:
#             handle_file_upload_encrypt(request, uploaded_file, password)
#             # messages.success(request, "Successfully uploaded data.")
#             return redirect("dashboard")
#         except (ValidationError, ConnectionFailure, KeyError) as e:
#             error_message = f"Internal Error Occurred: {str(e)}"
#             # messages.error(request, error_message)
#             print("[EXCEPTION]", e)  
#             return render(
#                 request, "upload.html", {'error': error_message}
#             ) 
#     else:
#         return render(request, "upload.html")


# @login_required
# def fetch_view(request):
#     if request.method == "GET":
#         username = request.user.username
#         collection = get_collection(username)
#         #user_uploads_cursor = collection.find({}, {"filename": 1, "upload_date": 1})
#         user_uploads=collection.query_items(f'select * from container con where con.username="{username}"',enable_cross_partition_query=True)
#         # for upload in user_uploads:
#         #     upload["id_str"] = str(upload["id"])
#         uploads_data = []  # Prepare data for rendering
#         for upload in user_uploads:
#             # Extract necessary information from the upload
#             upload_data = {
#                 "filename": upload.get("filename"),
#                 "upload_date": upload.get("upload_date"),
#                 "id_str": str(upload.get("id"))
#             }
#             uploads_data.append(upload_data) 
        
#         context = {"user_uploads": uploads_data}
        
#         return render(request, "fetch.html", context)
#     else:
#         return redirect("dashboard")  # Redirect to dashboard for non-GET requests

# @login_required
# def fetch_file_view(request, file_id):
#     password = password = request.POST.get("password")
#     context = {"file_id": file_id}
#     if password:
#         username = request.user.username
#         collection = get_collection(username)
#         #file_data = collection.find_one({"_id": ObjectId(file_id)})
#         file_data=collection.query_items(f'select * from container con where con.id="{file_id}"',enable_cross_partition_query=True)
#         #print(file_data)
#         encrypted_data = []  # Prepare encrypted data for decryption
#         for item in file_data:
#             encrypted_data=item.get("data", {})
#         #print(encrypted_data)
#         if encrypted_data:
#             try:
#                 decrypted_data = get_it_decrypted(encrypted_data, password)
#                 if decrypted_data:
#                     context["decrypted_data"] = decrypted_data
#                     messages.success(request, "Successfully decrypted data.")
#                 else:
#                     messages.error(request, "Decrypted Data is not returned.")
#             except ValueError as e:
#                 messages.error(request, "Wrong password. Please try again.")
#                 print("[EXCEPTION] ", e)
#         else:
#             messages.error(request, "File not found.")
#     messages_to_display = messages.get_messages(request)
#     context["messages"] = messages_to_display
#     return render(request, "fetch_file.html", context=context)

# from django.shortcuts import render

# @login_required
# def querydata_view(request):
#     if request.method == "GET":
#         username = request.user.username
        
#         # Assuming you have a function to get the collection/table
#         collection = get_collection(username)
        
#         # Assuming you have a function to query data from the collection/table
#         user_queries = collection.query_items(
#             f'select * from container con where con.username="{username}"',
#             enable_cross_partition_query=True
#         )
        
#         # Prepare data for rendering
#         query_data = []
#         for query in user_queries:
#             # Extract necessary information from the query
#             query_info = {
#                 "name": query.get("filename"),  # Assuming filename is the query name
#                 "creation_date": query.get("upload_date"),  # Assuming upload_date is the creation date
#             }
#             query_data.append(query_info)
        
#         context = {"user_queries": query_data}
        
#         return render(request, "querydata.html", context)
#     else:
#         return redirect("dashboard")



# # helper to upload file (just for testing)
# def handle_file_upload(request, file, password):
#     username = request.user.username
#     print(username)
#     collection = get_collection(username)
#     df = pd.read_csv(file)
    
#     # Drop rows with any missing values (NaNs)
#     df.dropna(inplace=True)
    
#     # Replace non-finite values (NaN, inf) with a default value (e.g., -1)
#     default_value = -1
#     float_columns = df.select_dtypes(include=['float']).columns
#     df[float_columns] = df[float_columns].replace([np.nan, np.inf, -np.inf], default_value)
    
#     # Convert float columns to integer dtype
#     for col in df.columns:
#         if df[col].dtype == float:
#             df[col] = df[col].astype(str)
    
#     # Convert DataFrame to dictionary
#     data_dict = df.to_dict(orient="records")
    
#     # Add additional information to data_dict
#     upload_date = datetime.datetime.now().isoformat()

#     file_id = str(uuid.uuid4())
    
#     data_dict = {
#         "id": file_id,
#         "username": username,
#         "filename": file.name,
#         "upload_date": upload_date,
#         "data": data_dict
#     }
    
#     print(type(data_dict))
   
#     json_data = json.dumps(data_dict)
#     print(type(json_data))
#     #collection.create_item(body={'id':'1','S.No': 32, 'NAME': 'JOTHIMANI M', 'YEAR': 'III CSE', 'BLOOD': 'B-', 'AGE': 19, 'CONTACT No.': 8883908536, 'LAST DONATED': '24.01.2018'})
#     #collection.upsert_item(body=data_dict)
#     #collection.insert_one(data_upload)


# # helper to upload file
# import hashlib

# def hash_message(message):
#     return hashlib.sha256(message.encode()).hexdigest()

# def handle_file_upload_encrypt(request, file, password):
#     try:
#         username = request.user.username
#         collection = get_collection(username)
#         file_id = str(uuid.uuid4())

#         # m = len(file_id)  # Maximum number of attributes
#         # d = 1  # Error tolerance
#         # p = 101  # Order of cyclic groups G and GT
#         # g = 2  # Generator of cyclic group G
#         # y = 7  # Example value for y
#         # public_params, master_key, T_values = setup(m, d, p, g, y)
#         # print("Public Parameters (PP):", public_params)
#         # print("Master Key (MK):", master_key)
#         # omega_ascii = [ord(c) for c in file_id]
#         # private_key = extract(public_params, master_key, omega_ascii, p, d, g, T_values)
#         # Dk = private_key['Dk']
#         # print('DK', Dk)
#         # print("Private Key:", private_key)

#         df = pd.read_csv(file, skiprows=1)
#         # print('Df', df)
#         # print('Df columns', df.columns)

#         # signatures = []
#         # for index, row in df.iterrows():
#         #     print("Row", row)
#         #     sign = calculate_signature(row, Dk)
#         #     signatures.append(sign)

#         newdf, sensitivity = get_it_encrypted(df, password)
#         data_length = len(newdf)
#         upload_date = datetime.datetime.now().isoformat()

#         # hashed_signatures = [hash_message(str(sign)) for sign in signatures]
        
#         #  # Create Merkle tree
#         # merkle_tree_data = create_merkle_tree(signatures)
#         # root_hash = merkle_tree_data["root_hash"]
#         # merkle_proofs = merkle_tree_data["merkle_proofs"]
        
#         data_with_blocks = [
#         {"data": row, "block_number": idx + 1}
#         for idx, row in enumerate(newdf.to_dict(orient="records"))
#         ]
        
#         tree = MerkleTree()
#         tree.makeTreeFromDataFrame(newdf)
#         tree.calculateMerkleRoot()
#         root = tree.getMerkleRoot()
#         print(root)

#         data_upload = {
#             "id": file_id,
#             "username": username,
#             "filename": file.name,
#             "upload_date": upload_date,
#             "data_with_blocks": data_with_blocks,
#             "sensitivity": sensitivity,
#             "data_length": data_length,
#             "root_hash" : root,
#         }
        
#         # Update data_upload dictionary
#         # for idx, row in enumerate(zip(signatures, newdf.itertuples(index=False))):
#         #     signature, _ = row
#         #     data_upload["data_with_signature"][idx]["merkle_proof"] = merkle_proofs[signature]
            
#         print(file_id)

#         TPA_ID_PUBLICPARAMS.append(file_id)

#         json_data_upload = json.dumps(data_upload)
#         data_dict = json.loads(json_data_upload)

#         collection.create_item(body=data_dict)
#         messages.success(request, "Successfully uploaded data.")

#     except Exception as e:
#         print("[EXCEPTION]", str(e))
#         traceback.print_exc()
#         raise e




# def create_initial_collection(collection_name):
#     try:
#         collection = get_collection(collection_name)
#         df = {
#             "msg": "This is a sample data uploaded at the time of your registration. Collection init successful"
#         }
#         upload_date = datetime.datetime.now().isoformat()
#         data_upload = {
#             "id": str(uuid.uuid4()),
#             "username": "infinull",
#             "filename": "initial-sample",
#             "upload_date": upload_date,
#             "data": df,
#         }
#         print(data_upload)
#         collection.create_item(body=data_upload)
#     except (ConnectionFailure, KeyError) as e:
#         raise Exception(f"Failed to create initial collection: {str(e)}")


# def get_collection(collection_name):
#     try:
#         #client = MongoClient("mongodb+srv://smoulikarthik:UdImqhIk9PqPOi3b@cluster0.rek4yhp.mongodb.net/")
#         # client = MongoClient("mongodb+srv://smoulikarthik:Akshaya.123@mongo-cosmos-host-proof.mongocluster.cosmos.azure.com/?tls=true&authMechanism=SCRAM-SHA-256&retrywrites=false&maxIdleTimeMS=120000")
#         # client.admin.command("ismaster")  # Check if connection is successful
#         # db = client["cloudsafe-db"]
#         database = client.create_database(DATABASE_NAME)
#         print('Database created')
#         container = database.create_container(id=CONTAINER_NAME,partition_key=PartitionKey(path='/id',kind='Hash'))
#         print('Created')
#         return container
#         #return db[collection_name]
#     except exceptions.CosmosResourceExistsError:
#         database = client.get_database_client(DATABASE_NAME)
#         container = database.get_container_client(CONTAINER_NAME)
#         print('already exists')
#         return container
#     except KeyError:
#         raise KeyError(f"Database '{collection_name}' not found.")


# # #-------------------------HASH FUNCTION---------------------------#
# # def hash_function(data_block):
# #   """
# #   Creates a SHA-256 signature for a given data block.

# #   Args:
# #       data_block: The data block (string or bytes) to be signed.

# #   Returns:
# #       The SHA-256 signature of the data block (hexadecimal string).
# #   """
# #   # Ensure data is converted to bytes for hashing
# #   if isinstance(data_block, str):
# #     data_block = data_block.encode()
  
# #   # Calculate the SHA-256 hash
# #   signature = sha256(data_block).hexdigest()
# #   return signature


# # #-------------------------CREATION OF MERKLE TREE-----------------#
# # def create_merkle_tree(data):
# #   """
# #   Creates a Merkle Tree from a Pandas DataFrame and returns the root hash
# #   along with a dictionary containing Merkle proofs for each data block.

# #   Args:
# #       data: A Pandas DataFrame containing the data to be hashed.

# #   Returns:
# #       A dictionary with two keys:
# #           - 'root_hash': The root hash (string) of the Merkle Tree.
# #           - 'proofs': A dictionary where keys are data block indices and
# #                       values are lists of sibling hashes (strings) for the proof.
# #   """

# #   if len(data) == 0:
# #     return None  # Handle empty DataFrame gracefully

# #   def create_proof(index, hashes):
# #     """
# #     Creates a Merkle proof for a data block at a specific index in the list.

# #     Args:
# #         index: The index of the data block in the original list.
# #         hashes: A list of combined hashes (strings) used for building the tree.

# #     Returns:
# #         A list of sibling hashes (strings) for the data block's proof.
# #     """
# #     proof = []
# #     while len(hashes) > 1:
# #       if index % 2 == 0:
# #         sibling_index = index + 1
# #       else:
# #         sibling_index = index - 1
# #       if sibling_index < 0 or sibling_index >= len(hashes):
# #         proof.append(None)  # Handle case where sibling doesn't exist
# #       else:
# #         proof.append(hashes[sibling_index])
# #       index //= 2
# #       hashes = [hashlib.sha256(h.encode()).hexdigest() for h in chain.from_iterable(zip(hashes[::2], hashes[1::2]))]
# #     return proof

# #   # Convert DataFrame to a list of row dictionaries for hashing
# #   data_list = data.to_dict(orient='records')

# #   # Create a list of SHA-256 hashes for each row dictionary
# #   hashed_data = [hashlib.sha256(str(row).encode()).hexdigest() for row in data_list]

# #   # Handle even or odd number of hashed values
# #   combined_hashes = []
# #   for i in range(0, len(hashed_data), 2):
# #     combined_data = hashed_data[i]
# #     if i + 1 < len(hashed_data):
# #       combined_data += hashed_data[i + 1]
# #     combined_hashes.append(hashlib.sha256(combined_data.encode()).hexdigest())


# #   # Recursive call to build the Merkle tree (return both root hash and proofs)
# #   # Iterative approach for building Merkle tree
# #   current_level_hashes = combined_hashes
# #   while len(current_level_hashes) > 1:
# #     next_level_hashes = []
# #     for i in range(0, len(current_level_hashes), 2):
# #       combined_data = current_level_hashes[i]
# #       if i + 1 < len(current_level_hashes):
# #         combined_data += current_level_hashes[i + 1]
# #       next_level_hashes.append(hashlib.sha256(combined_data.encode()).hexdigest())
# #     current_level_hashes = next_level_hashes

# #   # Root hash is the last element in the final level list
# #   root_hash = current_level_hashes[0]
# #   proofs = {}
# #   for i in range(len(hashed_data)):
# #     proofs[i] = create_proof(i, combined_hashes)  # Generate proof for each data block

# #   return {
# #     'root_hash': root_hash,
# #     'proofs': proofs,
# #   }



from django.shortcuts import render, redirect
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .forms import CustomUserCreationForm  
from django.core.mail import send_mail
from .models import VerificationResult
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
import django.contrib.messages as messages
from django.core.exceptions import ValidationError
from django.http import HttpResponse
import pandas as pd
import numpy as np
from pymongo.errors import ConnectionFailure
from cloudsafeapp.mechanism import get_it_encrypted, get_it_decrypted
from azure.cosmos import CosmosClient,exceptions,PartitionKey
from random import randint
import datetime
import json
import uuid
from itertools import chain
from io import StringIO
import traceback
from hashlib import sha256
from cloudsafeapp.merkle1 import MerkleTree
from .models import TaskHistory

# ---- Home and Error
URL = "https://host.documents.azure.com:443/"
KEY = "UI9FKIjChuwBbJW8PkhCuAwGvoKyH6fgi1ZskAXpcBVCmfcidARvXZ6JRyWwBThUxaQ9DjFnTVnmACDbzqfdEw=="

client = CosmosClient(URL,credential=KEY)

DATABASE_NAME = 'DB'
CONTAINER_NAME= "ITEMS"

TPA_ID_PUBLICPARAMS = []




def home_view(request):
    return render(request, "home.html")


def custom_404_view(request, exception):
    print("[EXCEPTION] ", exception)
    return render(request, "404.html", status=404)


# ---- AUTHENTICATION AND AUTHORIZATION


# def register_view(request):
  
def register_view(request):
    if request.method == "POST":
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
           
            try:
                # Assuming create_initial_collection is a custom function
                create_initial_collection(username)
            except Exception as e:
                messages.error(
                    request, f"Could not create a collection named {username}"
                )
                print("[EXCEPTION] ", e)
                return render(request, "register.html")
            user = form.save()
            login(request, user)
            messages.success(
                request, f"Welcome {username}! You have successfully registered."
            )
            return redirect("dashboard")
    else:
        form =CustomUserCreationForm()
    return render(request, "register.html", {"form": form})


def login_view(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(
                request, f"Welcome {user.username}! You have successfully logged in."
            )
            return redirect("dashboard")
    else:
        form = AuthenticationForm()
    messages_to_display = messages.get_messages(request)
    return render(
        request, "login.html", {"form": form, "messages": messages_to_display}
    )


def logout_view(request):
    logout(request)
    messages.success(request, "Successfully logged out.")
    return redirect("login")  # Redirect to login page after logout


# ---- DASHBOARD


@login_required
def dashboard_view(request):
    messages_to_display = messages.get_messages(request)
    return render(request, "dashboard.html", {"messages": messages_to_display})

@login_required
def delete_view(request, file_id):
    if request.method == "POST":
        try:
            username = request.user.username
            collection = get_collection(username)
            # Retrieve the item based on file_id
            items = collection.query_items(f'select * from c where c.id = "{file_id}"')
            item = next(items)
            # Delete the item
            collection.delete_item(item, partition_key=file_id)
            
            messages.success(request, "Successfully deleted the dataset.")
            return redirect("dashboard")
        except Exception as e:
           
            messages.error(request, f"Failed to delete the dataset: {str(e)}")
            return redirect("dashboard")
    return redirect("fetch")

# ---- FUNCTIONS
@login_required
# def activate_tpa_view(request):
#     if request.method == "POST":
#         username = request.user.username
#         collection = get_collection(username)
       
#         file_data = collection.query_items(
#         f'SELECT * FROM container con WHERE con.username="{username}"',
#         enable_cross_partition_query=True
#         )
        
        
        
        
#         encrypted_data = []
        
#         stored_root = ""
        
#         for item in file_data:
#             if "data_with_blocks" in item:
#                 data_blocks = item["data_with_blocks"]
#             if "root_hash" in item:
#                 stored_root = item["root_hash"]
        
#         for item in data_blocks:
#             if "data" in item:
#                 encrypted_data.append(item["data"])

        

       

#         df = pd.DataFrame(encrypted_data)
        
#         # Instantiate Merkle tree
#         merkle_tree = MerkleTree()
        
#         # Build Merkle tree from DataFrame
#         merkle_tree.makeTreeFromDataFrame(df)
        
#         # Calculate Merkle root
#         merkle_tree.calculateMerkleRoot()
        
#         # Get calculated Merkle root
#         calculated_root = merkle_tree.getMerkleRoot()
#         print("claculated_root",calculated_root)
#         print("stored_root",stored_root)
#         res = ""
        
#         if(stored_root == calculated_root):
#             res = "Data verified Successfully and the data is unchanged"
           
#             messages.success(request, res)
#         else:
#             res ="Data verified Successfully and the data have been tampered"
           
#             messages.warning(request, res)
#             # subject = "Data Integrity Alert"
#             # message = f"Dear {username},\n\nYour data has been tampered with. Please check your account for more details."
#             # recipient = request.user.email  # Assuming the User model has an email field
            
#             # send_email(
#             #     recipient,
#             #     subject,
#             #     message
#             # )
        
#         # Return a response
#         return redirect("dashboard")

def activate_tpa_view(request):

    username = request.user.username
    result = verify_data_integrity(username)
    
    # Log task history entry
    task_name = "TPA Activation"
    details = result['message']
    timestamp = datetime.datetime.now()
    user = request.user
    
    TaskHistory.objects.create(
        task_name=task_name,
        details=details,
        timestamp=timestamp,
        user=user
    )

    if result['status'] == 'tampered':
        messages.warning(request, result['message'])
    else:
        messages.success(request, result['message'])

    request.session['verification_result'] = result

    return redirect("dashboard")


def verify_data_integrity(username):
    collection = get_collection(username)
    file_data = collection.query_items(
        f'SELECT * FROM container con WHERE con.username="{username}"',
        enable_cross_partition_query=True
    )

    encrypted_data = []
    stored_root = ""
    
    for item in file_data:
        if "data_with_blocks" in item:
            data_blocks = item["data_with_blocks"]
        if "root_hash" in item:
            stored_root = item["root_hash"]

    for item in data_blocks:
        if "data" in item:
            encrypted_data.append(item["data"])

    df = pd.DataFrame(encrypted_data)
    
    merkle_tree = MerkleTree()
    merkle_tree.makeTreeFromDataFrame(df)
    merkle_tree.calculateMerkleRoot()
    calculated_root = merkle_tree.getMerkleRoot()
    
    if stored_root == calculated_root:
        return {'status': 'success', 'message': 'Data verified successfully and is unchanged.'}
    else:
        return {'status': 'tampered', 'message': 'Data verified successfully but has been tampered.'}

def verification_results_view(request):
     verification_result = request.session.get('verification_result')
    
    # Pass the verification result to the template
     context = {'verification_result': verification_result}
    
     return render(request, 'verification_results.html', context)

@login_required
def upload_view(request):
    if request.method == "POST" and request.FILES.get("file"):
        uploaded_file = request.FILES["file"]
        password = request.POST.get("password")
        try:
            handle_file_upload_encrypt(request, uploaded_file, password)
            # messages.success(request, "Successfully uploaded data.")
            return redirect("dashboard")
        except (ValidationError, ConnectionFailure, KeyError) as e:
            error_message = f"Internal Error Occurred: {str(e)}"
            # messages.error(request, error_message)
            print("[EXCEPTION]", e)  
            return render(
                request, "upload.html", {'error': error_message}
            ) 
    else:
        return render(request, "upload.html")


@login_required
def fetch_view(request):
    if request.method == "GET":
        username = request.user.username
        collection = get_collection(username)
        #user_uploads_cursor = collection.find({}, {"filename": 1, "upload_date": 1})
        user_uploads=collection.query_items(f'select * from container con where con.username="{username}"',enable_cross_partition_query=True)
        # for upload in user_uploads:
        #     upload["id_str"] = str(upload["id"])
        uploads_data = []  # Prepare data for rendering
        for upload in user_uploads:
            # Extract necessary information from the upload
            upload_data = {
                "filename": upload.get("filename"),
                "upload_date": upload.get("upload_date"),
                "id_str": str(upload.get("id"))
            }
            uploads_data.append(upload_data) 
        
        context = {"user_uploads": uploads_data}
        
        return render(request, "fetch.html", context)
    else:
        return redirect("dashboard")  # Redirect to dashboard for non-GET requests

@login_required
def fetch_file_view(request, file_id):
    password = password = request.POST.get("password")
    context = {"file_id": file_id}
    if password:
        username = request.user.username
        collection = get_collection(username)
        #file_data = collection.find_one({"_id": ObjectId(file_id)})
        file_data=collection.query_items(f'select * from container con where con.id="{file_id}"',enable_cross_partition_query=True)
        #print(file_data)
        encrypted_data = []  # Prepare encrypted data for decryption
        for item in file_data:
            encrypted_data=item.get("data", {})
        #print(encrypted_data)
        if encrypted_data:
            try:
                decrypted_data = get_it_decrypted(encrypted_data, password)
                if decrypted_data:
                    context["decrypted_data"] = decrypted_data
                    messages.success(request, "Successfully decrypted data.")
                else:
                    messages.error(request, "Decrypted Data is not returned.")
            except ValueError as e:
                messages.error(request, "Wrong password. Please try again.")
                print("[EXCEPTION] ", e)
        else:
            messages.error(request, "File not found.")
    messages_to_display = messages.get_messages(request)
    context["messages"] = messages_to_display
    return render(request, "fetch_file.html", context=context)

from django.shortcuts import render

@login_required
def querydata_view(request):
    if request.method == "GET":
        username = request.user.username
        
        # Assuming you have a function to get the collection/table
        collection = get_collection(username)
        
        # Assuming you have a function to query data from the collection/table
        user_queries = collection.query_items(
            f'select * from container con where con.username="{username}"',
            enable_cross_partition_query=True
        )
        
        # Prepare data for rendering
        query_data = []
        for query in user_queries:
            # Extract necessary information from the query
            query_info = {
                "name": query.get("filename"),  # Assuming filename is the query name
                "creation_date": query.get("upload_date"),  # Assuming upload_date is the creation date
            }
            query_data.append(query_info)
        
        context = {"user_queries": query_data}
        
        return render(request, "querydata.html", context)
    else:
        return redirect("dashboard")



# helper to upload file (just for testing)
def handle_file_upload(request, file, password):
    username = request.user.username
    print(username)
    collection = get_collection(username)
    df = pd.read_csv(file)
    
    # Drop rows with any missing values (NaNs)
    df.dropna(inplace=True)
    
    # Replace non-finite values (NaN, inf) with a default value (e.g., -1)
    default_value = -1
    float_columns = df.select_dtypes(include=['float']).columns
    df[float_columns] = df[float_columns].replace([np.nan, np.inf, -np.inf], default_value)
    
    # Convert float columns to integer dtype
    for col in df.columns:
        if df[col].dtype == float:
            df[col] = df[col].astype(str)
    
    # Convert DataFrame to dictionary
    data_dict = df.to_dict(orient="records")
    
    # Add additional information to data_dict
    upload_date = datetime.datetime.now().isoformat()

    file_id = str(uuid.uuid4())
    
    data_dict = {
        "id": file_id,
        "username": username,
        "filename": file.name,
        "upload_date": upload_date,
        "data": data_dict
    }
    
    print(type(data_dict))
   
    json_data = json.dumps(data_dict)
    print(type(json_data))
    #collection.create_item(body={'id':'1','S.No': 32, 'NAME': 'JOTHIMANI M', 'YEAR': 'III CSE', 'BLOOD': 'B-', 'AGE': 19, 'CONTACT No.': 8883908536, 'LAST DONATED': '24.01.2018'})
    #collection.upsert_item(body=data_dict)
    #collection.insert_one(data_upload)


# helper to upload file
import hashlib

def hash_message(message):
    return hashlib.sha256(message.encode()).hexdigest()

def handle_file_upload_encrypt(request, file, password):
    try:
        username = request.user.username
        collection = get_collection(username)
        file_id = str(uuid.uuid4())

        # m = len(file_id)  # Maximum number of attributes
        # d = 1  # Error tolerance
        # p = 101  # Order of cyclic groups G and GT
        # g = 2  # Generator of cyclic group G
        # y = 7  # Example value for y
        # public_params, master_key, T_values = setup(m, d, p, g, y)
        # print("Public Parameters (PP):", public_params)
        # print("Master Key (MK):", master_key)
        # omega_ascii = [ord(c) for c in file_id]
        # private_key = extract(public_params, master_key, omega_ascii, p, d, g, T_values)
        # Dk = private_key['Dk']
        # print('DK', Dk)
        # print("Private Key:", private_key)

        df = pd.read_csv(file, skiprows=1)
        # print('Df', df)
        # print('Df columns', df.columns)

        # signatures = []
        # for index, row in df.iterrows():
        #     print("Row", row)
        #     sign = calculate_signature(row, Dk)
        #     signatures.append(sign)

        newdf, sensitivity = get_it_encrypted(df, password)
        data_length = len(newdf)
        upload_date = datetime.datetime.now().isoformat()

        # hashed_signatures = [hash_message(str(sign)) for sign in signatures]
        
        #  # Create Merkle tree
        # merkle_tree_data = create_merkle_tree(signatures)
        # root_hash = merkle_tree_data["root_hash"]
        # merkle_proofs = merkle_tree_data["merkle_proofs"]
        
        data_with_blocks = [
        {"data": row, "block_number": idx + 1}
        for idx, row in enumerate(newdf.to_dict(orient="records"))
        ]
        
        tree = MerkleTree()
        tree.makeTreeFromDataFrame(newdf)
        tree.calculateMerkleRoot()
        root = tree.getMerkleRoot()
        print(root)

        data_upload = {
            "id": file_id,
            "username": username,
            "filename": file.name,
            "upload_date": upload_date,
            "data_with_blocks": data_with_blocks,
            "sensitivity": sensitivity,
            "data_length": data_length,
            "root_hash" : root,
        }
        
        # Update data_upload dictionary
        # for idx, row in enumerate(zip(signatures, newdf.itertuples(index=False))):
        #     signature, _ = row
        #     data_upload["data_with_signature"][idx]["merkle_proof"] = merkle_proofs[signature]
            
        print(file_id)

        TPA_ID_PUBLICPARAMS.append(file_id)

        json_data_upload = json.dumps(data_upload)
        data_dict = json.loads(json_data_upload)

        collection.create_item(body=data_dict)
        messages.success(request, "Successfully uploaded data.")

    except Exception as e:
        print("[EXCEPTION]", str(e))
        traceback.print_exc()
        raise e




def create_initial_collection(collection_name):
    try:
        collection = get_collection(collection_name)
        df = {
            "msg": "This is a sample data uploaded at the time of your registration. Collection init successful"
        }
        upload_date = datetime.datetime.now().isoformat()
        data_upload = {
            "id": str(uuid.uuid4()),
            "username": "infinull",
            "filename": "initial-sample",
            "upload_date": upload_date,
            "data": df,
        }
        print(data_upload)
        collection.create_item(body=data_upload)
    except (ConnectionFailure, KeyError) as e:
        raise Exception(f"Failed to create initial collection: {str(e)}")


def get_collection(collection_name):
    try:
        #client = MongoClient("mongodb+srv://smoulikarthik:UdImqhIk9PqPOi3b@cluster0.rek4yhp.mongodb.net/")
        # client = MongoClient("mongodb+srv://smoulikarthik:Akshaya.123@mongo-cosmos-host-proof.mongocluster.cosmos.azure.com/?tls=true&authMechanism=SCRAM-SHA-256&retrywrites=false&maxIdleTimeMS=120000")
        # client.admin.command("ismaster")  # Check if connection is successful
        # db = client["cloudsafe-db"]
        database = client.create_database(DATABASE_NAME)
        print('Database created')
        container = database.create_container(id=CONTAINER_NAME,partition_key=PartitionKey(path='/id',kind='Hash'))
        print('Created')
        return container
        #return db[collection_name]
    except exceptions.CosmosResourceExistsError:
        database = client.get_database_client(DATABASE_NAME)
        container = database.get_container_client(CONTAINER_NAME)
        print('already exists')
        return container
    except KeyError:
        raise KeyError(f"Database '{collection_name}' not found.")
    


def task_history_view(request):
    # Retrieve all task history entries from the database
 
    task_history = TaskHistory.objects.order_by('-timestamp')
    return render(request, 'task_history.html', {'task_history': task_history})


@login_required
def dashboard_view(request):
    # Retrieve all task history entries from the database
    task_history_entries = TaskHistory.objects.all()

    # Pass the task history entries to the template
    context = {'task_history_entries': task_history_entries}

    return render(request, 'dashboard.html', context)




# @login_required
# def dashboard_view(request):
#     task_history_entries = TaskHistory.objects.filter(user=request.user).order_by('-timestamp')
#     context = {'task_history_entries': task_history_entries}
#     return render(request, 'dashboard.html', context)

# @login_required
# def activate_tpa_view(request):
#     if request.method == "POST":
#         activate_tpa_task.delay()  # Schedule the task
#         messages.success(request, "TPA activation task has been scheduled.")
#         return redirect("dashboard")
#     else:
#         return render(request, 'dashboard.html')


