def chunk_text(text, chunk_size=1000):
    """
    Splits text into chunks of given size (by characters)
    """
    return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]


def chunk_lines(text, lines_per_chunk=100):
    """
    Splits text into chunks based on number of lines
    """
    lines = text.split("\n")
    chunks = []

    for i in range(0, len(lines), lines_per_chunk):
        chunk = "\n".join(lines[i:i + lines_per_chunk])
        chunks.append(chunk)

    return chunks