with open("frontend/Watchlist.py", "r") as f:
    content = f.read()

import re
pattern = r"<<<<<<< Updated upstream.*?=======\n(.*?)>>>>>>> Stashed changes\n"
content = re.sub(pattern, r"\1", content, flags=re.DOTALL)

with open("frontend/Watchlist.py", "w") as f:
    f.write(content)
