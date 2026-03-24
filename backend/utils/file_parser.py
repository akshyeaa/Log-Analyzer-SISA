from langchain.document_loaders import PyPDFLoader
from docx import Document

def parse_file(file_path, file_type):
    if file_type == "pdf":
        loader = PyPDFLoader(file_path)
        docs = loader.load()
        return "\n".join([doc.page_content for doc in docs])

    elif file_type == "docx":
        doc = Document(file_path)
        return "\n".join([para.text for para in doc.paragraphs])

    elif file_type in ["txt", "log"]:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()

    return ""