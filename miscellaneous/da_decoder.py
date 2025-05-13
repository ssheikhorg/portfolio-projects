import httpx
from bs4 import BeautifulSoup
from typing import List, Tuple


def fetch_and_parse_data(doc_url: str) -> List[Tuple[int, int, str]]:
    with httpx.Client() as client:
        response = client.get(doc_url)
        if response.status_code != 200:
            raise Exception("Failed to fetch the document")
        soup = BeautifulSoup(response.content, 'html.parser')
        table_rows = soup.find_all('tr')
        grid_data = []
        for row in table_rows[1:]:
            cells = row.find_all('td')
            if len(cells) == 3:
                x = int(cells[0].text.strip())
                char = cells[1].text.strip().upper()
                y = int(cells[2].text.strip())
                grid_data.append((x, y, char))
        return grid_data


def decode_secret_message(doc_url: str) -> None:
    grid_data = fetch_and_parse_data(doc_url)
    max_x = max(x for x, y, char in grid_data)
    max_y = max(y for x, y, char in grid_data)
    grid = [[' ' for _ in range(max_x + 1)] for _ in range(max_y + 1)]
    for x, y, char in grid_data:
        grid[y][x] = char
    for row in grid:
        print("".join(row))



if __name__ == "__main__":
    doc_url = "https://docs.google.com/document/d/e/2PACX-1vQGUck9HIFCyezsrBSnmENk5ieJuYwpt7YHYEzeNJkIb9OSDdx-ov2nRNReKQyey-cwJOoEKUhLmN9z/pub"
    decode_secret_message(doc_url)
