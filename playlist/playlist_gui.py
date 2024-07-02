
import json
from PyQt5.QtWidgets import (QWidget, QPushButton, QVBoxLayout, QLineEdit,
                             QFormLayout, QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QHBoxLayout, QMessageBox)
from PyQt5.QtCore import QTime

from .utils import validate_name, validate_time, validate_days, show_error_message


class ScheduleManager(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setGeometry(300, 300, 600, 400)
        self.setWindowTitle('Playlist Schedule Manager')

        layout = QVBoxLayout()
        form_layout = QFormLayout()

        self.name_input = QLineEdit(self)
        self.name_input.setText('Name')

        self.time_input = QLineEdit(self)
        self.time_input.setText('12:00')

        self.days_input = QLineEdit(self)
        self.days_input.setText('0,1,2,3,4,5,6')

        self.folder_input = QLineEdit(self)
        self.folder_input.setText('Folder')

        form_layout.addRow(QLabel('Playlist Name:'), self.name_input)
        form_layout.addRow(QLabel('Start Time (HH:MM):'), self.time_input)
        form_layout.addRow(QLabel('Days (comma-separated):'), self.days_input)
        form_layout.addRow(QLabel('Folder Path:'), self.folder_input)

        self.load_button = QPushButton('Load Playlist', self)
        self.load_button.clicked.connect(self.load_playlist)

        self.add_button = QPushButton('Add Playlist', self)
        self.add_button.clicked.connect(self.add_playlist)

        self.delete_button = QPushButton('Delete Selected', self)
        self.delete_button.clicked.connect(self.delete_selected_playlist)

        self.save_button = QPushButton('Save', self)
        self.save_button.clicked.connect(self.save_schedule)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.load_button)
        button_layout.addWidget(self.add_button)
        button_layout.addWidget(self.delete_button)
        button_layout.addWidget(self.save_button)

        layout.addLayout(form_layout)
        layout.addLayout(button_layout)

        self.table_widget = QTableWidget()
        self.table_widget.setColumnCount(5)
        self.table_widget.setHorizontalHeaderLabels(['Name', 'Start Time', 'Days', 'Folder', 'Duration'])
        self.table_widget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table_widget)

        self.setLayout(layout)
        print("UI Initialized")

    def add_playlist(self):
        print("Adding playlist")
        name = self.name_input.text()
        start_time = self.time_input.text()
        days = self.days_input.text()
        folder = self.folder_input.text()

        if not validate_name(name):
            show_error_message("Invalid Playlist Name",
                               "The playlist name must be a valid name with a maximum length of 40 characters.")
            return
        if not validate_time(start_time):
            show_error_message("Invalid Start Time", "The start time must be in HH:MM 24-hour format.")
            return
        if not validate_days(days):
            show_error_message("Invalid Days",
                               "The days must be a comma-separated list of numbers (e.g., 0,1,2,3,4,5,6).")
            return
        if self.check_for_overlap(start_time, days):
            show_error_message("Overlapping Start Time",
                               "Another playlist is already scheduled to start at this time on the same days.")
            return

        row_position = self.table_widget.rowCount()
        self.table_widget.insertRow(row_position)
        self.table_widget.setItem(row_position, 0, QTableWidgetItem(name))
        self.table_widget.setItem(row_position, 1, QTableWidgetItem(start_time))
        self.table_widget.setItem(row_position, 2, QTableWidgetItem(days))
        self.table_widget.setItem(row_position, 3, QTableWidgetItem(folder))

        self.sort_table()
        self.update_durations()

    def delete_selected_playlist(self):
        selected_row = self.table_widget.currentRow()
        if selected_row != -1:
            confirm = QMessageBox.question(self, 'Confirm Deletion',
                                           'Are you sure you want to delete the selected playlist?',
                                           QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if confirm == QMessageBox.Yes:
                self.table_widget.removeRow(selected_row)
                self.sort_table()
                self.update_durations()

    def check_for_overlap(self, start_time, days):
        new_start_time = QTime.fromString(start_time, "HH:mm")
        new_days = set(days.split(','))
        for row in range(self.table_widget.rowCount()):
            existing_start_time_item = self.table_widget.item(row, 1)
            existing_days_item = self.table_widget.item(row, 2)
            if existing_start_time_item and existing_days_item:
                existing_start_time = QTime.fromString(existing_start_time_item.text(), "HH:mm")
                existing_days = set(existing_days_item.text().split(','))
                if new_start_time == existing_start_time and new_days.intersection(existing_days):
                    return True
        return False

    def sort_table(self):
        print("Sorting table")
        rows = []
        for row in range(self.table_widget.rowCount()):
            name_item = self.table_widget.item(row, 0)
            start_time_item = self.table_widget.item(row, 1)
            days_item = self.table_widget.item(row, 2)
            folder_item = self.table_widget.item(row, 3)
            duration_item = self.table_widget.item(row, 4)

            if name_item and start_time_item and days_item and folder_item:
                name = name_item.text()
                start_time = start_time_item.text()
                days = days_item.text()
                folder = folder_item.text()
                duration = duration_item.text() if duration_item else ""
                rows.append((name, start_time, days, folder, duration))

        rows.sort(key=lambda x: QTime.fromString(x[1], "HH:mm"))

        self.table_widget.setRowCount(0)
        for row_data in rows:
            row_position = self.table_widget.rowCount()
            self.table_widget.insertRow(row_position)
            for col, item in enumerate(row_data):
                self.table_widget.setItem(row_position, col, QTableWidgetItem(item))

        self.update_durations()

    def update_durations(self):
        print("Updating durations")
        row_count = self.table_widget.rowCount()
        end_of_day = QTime(23, 59)
        start_of_day = QTime(0, 0)
        gaps = []

        for row in range(row_count):
            start_time_item = self.table_widget.item(row, 1)
            days_item = self.table_widget.item(row, 2)
            start_time = QTime.fromString(start_time_item.text(), "HH:mm")
            days = set(days_item.text().split(','))

            next_start_time = None
            next_days = None

            for next_row in range(row + 1, row_count):
                next_start_time_item = self.table_widget.item(next_row, 1)
                next_days_item = self.table_widget.item(next_row, 2)
                next_start_time = QTime.fromString(next_start_time_item.text(), "HH:mm")
                next_days = set(next_days_item.text().split(','))
                if days.intersection(next_days):
                    break
                next_start_time = None
                next_days = None

            if next_start_time:
                duration_secs = start_time.secsTo(next_start_time)
                if duration_secs < 0:
                    duration_secs += 24 * 3600  # Account for crossing midnight
                hours, remainder = divmod(duration_secs, 3600)
                minutes = remainder // 60
                duration_str = f"{hours} hours {minutes} minutes"
                self.table_widget.setItem(row, 4, QTableWidgetItem(duration_str))
            else:
                duration_secs = start_time.secsTo(end_of_day) + 60  # Until end of the day
                if row == 0:
                    duration_secs += 24 * 3600  # Add 24 hours for the first entry
                hours, remainder = divmod(duration_secs, 3600)
                minutes = remainder // 60
                duration_str = f"{hours} hours {minutes} minutes"
                self.table_widget.setItem(row, 4, QTableWidgetItem(duration_str))

                if row_count > 1:
                    gaps.append(days)

        self.fill_gaps()

    def fill_gaps(self):
        print("Filling gaps")
        row_count = self.table_widget.rowCount()
        total_duration = 0

        for row in range(row_count):
            duration_item = self.table_widget.item(row, 4)
            if duration_item:
                duration_text = duration_item.text().split()
                hours = int(duration_text[0])
                minutes = int(duration_text[2])
                total_duration += hours * 3600 + minutes * 60

        remaining_duration = 24 * 3600 - total_duration

        if remaining_duration > 0:
            last_entry_end_time = QTime.fromString(self.table_widget.item(row_count - 1, 1).text(), "HH:mm").addSecs(
                int(self.table_widget.item(row_count - 1, 4).text().split()[0]) * 3600 + int(
                    self.table_widget.item(row_count - 1, 4).text().split()[2]) * 60)
            new_entry = {
                'name': 'Auto Generated',
                'start_time': last_entry_end_time.toString("HH:mm"),
                'days': self.table_widget.item(row_count - 1, 2).text(),
                'folder': 'Auto Generated Folder',
                'duration': f'{remaining_duration // 3600} hours {remaining_duration % 3600 // 60} minutes'
            }
            row_position = self.table_widget.rowCount()
            self.table_widget.insertRow(row_position)
            self.table_widget.setItem(row_position, 0, QTableWidgetItem(new_entry['name']))
            self.table_widget.setItem(row_position, 1, QTableWidgetItem(new_entry['start_time']))
            self.table_widget.setItem(row_position, 2, QTableWidgetItem(new_entry['days']))
            self.table_widget.setItem(row_position, 3, QTableWidgetItem(new_entry['folder']))
            self.table_widget.setItem(row_position, 4, QTableWidgetItem(new_entry['duration']))

    def save_schedule(self):
        print("Saving schedule")
        schedule = []
        for row in range(self.table_widget.rowCount()):
            name_item = self.table_widget.item(row, 0)
            start_time_item = self.table_widget.item(row, 1)
            days_item = self.table_widget.item(row, 2)
            folder_item = self.table_widget.item(row, 3)
            duration_item = self.table_widget.item(row, 4)

            if name_item and start_time_item and days_item and folder_item:
                name = name_item.text()
                start_time = start_time_item.text()
                days = days_item.text()
                folder = folder_item.text()
                duration = duration_item.text() if duration_item else ""
                schedule.append({
                    'name': name,
                    'start_time': start_time,
                    'days': days,
                    'folder': folder,
                    'duration': duration
                })

        with open('config.json', 'w') as f:
            json.dump(schedule, f, indent=4)
        print("Schedule saved to config.json")

    def load_playlist(self):
        print("Loading schedule")
        try:
            with open('playlists.json', 'r') as f:
                schedule = json.load(f)
                for entry in schedule:
                    row_position = self.table_widget.rowCount()
                    self.table_widget.insertRow(row_position)
                    self.table_widget.setItem(row_position, 0, QTableWidgetItem(entry['name']))
                    self.table_widget.setItem(row_position, 1, QTableWidgetItem(entry['start_time']))
                    self.table_widget.setItem(row_position, 2, QTableWidgetItem(entry['days']))
                    self.table_widget.setItem(row_position, 3, QTableWidgetItem(entry['folder']))
                    self.table_widget.setItem(row_position, 4, QTableWidgetItem(entry['duration']))
                self.sort_table()
                self.update_durations()
        except FileNotFoundError:
            show_error_message("No existing schedule found", "No existing schedule found, starting fresh.")
