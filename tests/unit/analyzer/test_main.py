import pytest
import sys
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path

from src.analyzer.main import main

MODULE_PATH = "src.analyzer.main"

@pytest.fixture
def existing_file(tmp_path):
    f = tmp_path / "test.log"
    f.touch()
    return f

def test_main_no_arguments():
    with patch.object(sys, 'argv', ['prog_name']):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code != 0

@patch(f"{MODULE_PATH}.LogStreamer")
@patch(f"{MODULE_PATH}.ThreatDetector")
@patch(f"{MODULE_PATH}.ConsoleWriter")
def test_main_happy_path_text(MockConsoleWriter, MockDetector, MockStreamer, existing_file):
    
    with patch.object(sys, 'argv', ['main.py', str(existing_file)]):
        main()
    
    MockStreamer.return_value.stream_merged_logs.assert_called_once()
    call_args = MockStreamer.return_value.stream_merged_logs.call_args[0][0]
    assert call_args == [existing_file]
    
    MockDetector.return_value.analyze_stream.assert_called_once()
    
    MockConsoleWriter.return_value.write.assert_called_once()

@patch(f"{MODULE_PATH}.LogStreamer")
@patch(f"{MODULE_PATH}.ThreatDetector")
@patch(f"{MODULE_PATH}.JsonWriter")
def test_main_json_format_with_output_file(MockJsonWriter, MockDetector, MockStreamer, existing_file, tmp_path):
    output_file = tmp_path / "report.json"
    
    cmd = ['main.py', str(existing_file), '-f', 'json', '-o', str(output_file)]
    
    with patch.object(sys, 'argv', cmd):
        main()
        
    MockJsonWriter.return_value.write.assert_called_once()
    
    args, kwargs =MockJsonWriter.return_value.write.call_args
    destination = kwargs['destination']
    assert destination.name == str(output_file)
    assert destination.mode == 'w'

@patch(f"{MODULE_PATH}.logger") 
def test_main_no_valid_files(mock_logger):
    with patch.object(sys, 'argv', ['main.py', 'ghost_file.log']):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 1 
    
    mock_logger.error.assert_called_with("No valid input files provided.")

@patch(f"{MODULE_PATH}.LogStreamer")
def test_main_keyboard_interrupt(MockStreamer, existing_file):
    MockStreamer.return_value.stream_merged_logs.side_effect = KeyboardInterrupt
    
    with patch.object(sys, 'argv', ['main.py', str(existing_file)]):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 130

@patch(f"{MODULE_PATH}.LogStreamer")
@patch(f"{MODULE_PATH}.logger")
def test_main_unexpected_exception(mock_logger, MockStreamer, existing_file):
    MockStreamer.return_value.stream_merged_logs.side_effect = RuntimeError("Fatal error")
    
    with patch.object(sys, 'argv', ['main.py', str(existing_file)]):
        with pytest.raises(SystemExit) as e:
            main()
        assert e.value.code == 1
    
    assert mock_logger.critical.called
    assert "Unexpected error" in mock_logger.critical.call_args[0][0]

@patch(f"{MODULE_PATH}.LogStreamer")
@patch(f"{MODULE_PATH}.ThreatDetector")
@patch(f"{MODULE_PATH}.ConsoleWriter")
def test_main_mixed_files(MockWriter, MockDetector, MockStreamer, existing_file):
    missing_file = Path("ghost.log")
    
    with patch.object(sys, 'argv', ['main.py', str(existing_file), str(missing_file)]):
        main()
    
    call_args = MockStreamer.return_value.stream_merged_logs.call_args[0][0]
    assert len(call_args) == 1
    assert call_args[0] == existing_file