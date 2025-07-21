<?php
// =================================================================
// ALL-IN-ONE CRM SYSTEM
// =================================================================
// Start session at the very top
session_start();
//session start
//this is test file
include 'db.php'; // <-- MOVED HERE. This creates the $conn variable.
date_default_timezone_set('Asia/Kolkata');
require 'vendor/autoload.php';
// =================================================================
//added requir code
use PhpOffice\PhpSpreadsheet\IOFactory;
use PhpOffice\PhpSpreadsheet\Spreadsheet;

define('SESSION_TIMEOUT', 7200); // 2 hours = 2 * 60 * 60 = 7200 seconds

// This check runs only if the user is already logged in
if (isset($_SESSION['otp_verified'])) {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
        // If the last activity was more than 2 hours ago, log them out.
        $username = $_SESSION['username'] ?? 'User';
        if (isset($_SESSION['login_log_id'])) {
            $log_id = $_SESSION['login_log_id'];
            $logout_stmt = $conn->prepare("UPDATE login_logs SET logout_time = NOW() WHERE id = ?");
            $logout_stmt->bind_param("i", $log_id);
            $logout_stmt->execute();
            $logout_stmt->close();
        }

        session_unset();     // Unset $_SESSION variable for the run-time
        session_destroy();   // Destroy session data in storage

        // Redirect to login page with a message
        header("Location: index.php?message=" . urlencode("$username, you have been logged out due to inactivity."));
        exit();
    }
    // If they are not timed out, update their last activity time to now.
    $_SESSION['last_activity'] = time();
}
// =================================================================
// DATABASE & CORE FUNCTIONS
// =================================================================

// $host = "localhost";
// $user = "root";
// $password = "";
// $dbname = "crm";

// $conn = new mysqli($host, $user, $password, $dbname);
// if ($conn->connect_error) {
//     die("Connection failed: " . $conn->connect_error);
// }

// --- Helper Functions ---

// function sendOTP($email, $otp)
// {
//     $to = $email;
//     $cc = "jayaprakshprusty546@gmail.com";
//     $subject = "Your OTP for CRM Login";
//     $message = "Your One-Time Password is: $otp";
//     $headers = "From: noreply@yourcrm.com\r\nCC: $cc";
//     @mail($to, $subject, $message, $headers);
// }
function sendOTP($email, $otp)
{
    $to = $email;
    $cc1 = "shuvam@theuniqueculture.com";
    $cc2 = "info@theuniqueculture.com"; // Replace with the second CC email
    $subject = "Your OTP for CRM Login";
    $message = "Your One-Time Password is: $otp";

    $headers = "From: noreply@yourcrm.com\r\n";
    $headers .= "Cc: $cc1, $cc2";

    @mail($to, $subject, $message, $headers);
}


define('ENCRYPTION_KEY', 'e4a2e5b7f8c1d6a3b9e0f3a7c8b5d2e1');
define('ENCRYPTION_IV', 'a1b2c3d4e5f6a7b8');

function encryptData($data)
{
    if ($data === null || $data === '') return null;
    return base64_encode(openssl_encrypt($data, 'AES-256-CBC', ENCRYPTION_KEY, 0, ENCRYPTION_IV));
}

function decryptData($data)
{
    if ($data === null || $data === '') return null;
    return openssl_decrypt(base64_decode($data), 'AES-256-CBC', ENCRYPTION_KEY, 0, ENCRYPTION_IV);
}
function formatPhoneNumber($number)
{
    if (empty($number) || !is_numeric($number)) {
        return $number; // Return original if not a valid number
    }

    if (strlen($number) > 5) {
        return substr($number, 0, 5) . '-' . substr($number, 5);
    } else {
        return $number; // Return as is if 5 digits or less
    }
}

function generatePagination($total_items, $per_page, $current_page, $base_url)
{
    $total_pages = ceil($total_items / $per_page);
    if ($total_pages <= 1) {
        return '';
    }

    $html = '<div class="pagination-container">';
    $html .= '<div class="pagination-summary">Showing ' . (($current_page - 1) * $per_page + 1) . ' to ' . min($current_page * $per_page, $total_items) . ' of ' . $total_items . ' results</div>';
    $html .= '<ul class="pagination">';

    // Previous button
    if ($current_page > 1) {
        $html .= '<li><a href="' . $base_url . '&page=' . ($current_page - 1) . '">« Prev</a></li>';
    } else {
        $html .= '<li class="disabled"><span>« Prev</span></li>';
    }

    // Page number links
    for ($i = 1; $i <= $total_pages; $i++) {
        if ($i == $current_page) {
            $html .= '<li class="active"><span>' . $i . '</span></li>';
        } else {
            $html .= '<li><a href="' . $base_url . '&page=' . $i . '">' . $i . '</a></li>';
        }
    }

    // Next button
    if ($current_page < $total_pages) {
        $html .= '<li><a href="' . $base_url . '&page=' . ($current_page + 1) . '">Next »</a></li>';
    } else {
        $html .= '<li class="disabled"><span>Next »</span></li>';
    }

    $html .= '</ul></div>';
    return $html;
}
$status_options = [];
$status_result = $conn->query("SELECT name, color FROM statuses ORDER BY name ASC");
while ($row = $status_result->fetch_assoc()) {
    $status_options[$row['name']] = $row['color'];
}

// --- Requirements ---
$requirement_options = [];
$req_result = $conn->query("SELECT name FROM requirements ORDER BY name ASC");
while ($row = $req_result->fetch_assoc()) {
    $requirement_options[] = $row['name'];
}
$requirement_options[] = 'Other'; // Always ensure 'Other' is an option

// --- Communication Modes ---
$communication_mode_options = [];
$comm_result = $conn->query("SELECT name FROM communication_modes ORDER BY name ASC");
while ($row = $comm_result->fetch_assoc()) {
    $communication_mode_options[] = $row['name'];
}
$communication_mode_options[] = 'Other';

if (isset($_POST['ajax_update'])) {
    header('Content-Type: application/json');
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['status' => 'error', 'message' => 'Authentication required.']);
        exit();
    }
    if (!isset($_POST['lead_id'], $_POST['field'], $_POST['value'])) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid parameters.']);
        exit();
    }
    $lead_id = intval($_POST['lead_id']);
    $field = $_POST['field'];
    $value = $_POST['value'];
    $allowed_fields = ['status', 'requirement', 'communication_mode', 'followup_date', 'next_followup_date'];
    if (!in_array($field, $allowed_fields)) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid field specified for update.']);
        exit();
    }

    // Permission Check (Unchanged)
    $current_user_id = $_SESSION['user_id'];
    $current_user_role = $_SESSION['role'];
    $has_permission = false;
    if ($current_user_role === 'admin' || $current_user_role === 'manager') {
        $has_permission = true;
    } else {
        $perm_stmt = $conn->prepare("SELECT user_id FROM leads WHERE id = ?");
        $perm_stmt->bind_param("i", $lead_id);
        $perm_stmt->execute();
        $result = $perm_stmt->get_result();
        if ($lead = $result->fetch_assoc()) {
            if ($lead['user_id'] == $current_user_id) {
                $has_permission = true;
            }
        }
        $perm_stmt->close();
    }
    if (!$has_permission) {
        echo json_encode(['status' => 'error', 'message' => 'Permission denied.']);
        exit();
    }

    // Prepare value for DB (Unchanged)
    if ($field === 'status' || $field === 'requirement' || $field === 'communication_mode') {
        $db_value = encryptData($value);
    } elseif ($field === 'followup_date' || $field === 'next_followup_date') {
        $db_value = !empty($value) ? $value : null;
    } else {
        $db_value = $value;
    }

    // Main update query
    $update_stmt = $conn->prepare("UPDATE leads SET `$field` = ? WHERE id = ?");
    $update_stmt->bind_param("si", $db_value, $lead_id);

    if ($update_stmt->execute()) {
        $response = ['status' => 'success', 'message' => 'Lead updated.'];

        // If a followup_date was successfully updated, log it and return the new entry
        if ($field === 'followup_date' && !empty($db_value)) {
            $history_stmt = $conn->prepare("INSERT INTO followup_history (lead_id, user_id, followup_date) VALUES (?, ?, ?)");
            $history_stmt->bind_param("iis", $lead_id, $current_user_id, $db_value);
            $history_stmt->execute();
            $history_stmt->close();

            if (isset($_SESSION['login_log_id'])) {
                $call_count_stmt = $conn->prepare("UPDATE login_logs SET call_count = call_count + 1 WHERE id = ?");
                $call_count_stmt->bind_param("i", $_SESSION['login_log_id']);
                $call_count_stmt->execute();
                $call_count_stmt->close();
            }
            // Prepare the new history entry to send back to the JavaScript
            $response['new_history_entry'] = [
                'followup_date' => $db_value,
                'username' => $_SESSION['username'] // The user who just made the change
            ];
        }
        echo json_encode($response);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Database update failed: ' . $update_stmt->error]);
    }

    $update_stmt->close();
    exit();
}
if (isset($_POST['get_batches_for_user'])) {
    header('Content-Type: application/json');
    if (!isset($_SESSION['user_id'])) {
        echo json_encode(['status' => 'error', 'message' => 'Authentication required.']);
        exit();
    }

    $userId = intval($_POST['user_id']);
    $batches = [];

    // Simple security check: Non-admins/managers can only get their own batches
    if ($_SESSION['role'] === 'member' && $userId != $_SESSION['user_id']) {
        echo json_encode(['status' => 'error', 'message' => 'Permission Denied.']);
        exit();
    }

    $stmt = $conn->prepare("SELECT DISTINCT source_file FROM leads WHERE user_id = ? AND source_file IS NOT NULL ORDER BY source_file ASC");
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result();

    while ($row = $result->fetch_assoc()) {
        $batches[] = $row['source_file'];
    }

    $stmt->close();
    echo json_encode(['status' => 'success', 'batches' => $batches]);
    exit();
}

// =================================================================
// ACTION HANDLER
// =================================================================
if (isset($_GET['download_template'])) {
    // Ensure the user is logged in to download the template
    if (!isset($_SESSION['otp_verified'])) {
        header("Location: index.php");
        exit();
    }

    $spreadsheet = new Spreadsheet();
    $sheet = $spreadsheet->getActiveSheet();
    $sheet->setTitle('Leads Import Template');

    // Define the headers based on the import logic
    $headers = [
        'Name',
        'Phone',
        'Status (Optional)',
        'Followup Date (YYYY-MM-DD)',
        'Next Followup Date (YYYY-MM-DD)',
        'Requirement',
        'Source',
        'Feedback',
        'Service'
    ];

    // Write headers to the first row of the spreadsheet
    $sheet->fromArray($headers, NULL, 'A1');

    // Apply bold styling to the header row
    $sheet->getStyle('A1:I1')->getFont()->setBold(true);

    // Auto-size columns for better readability
    foreach (range('A', 'I') as $columnID) {
        $sheet->getColumnDimension($columnID)->setAutoSize(true);
    }

    // Set the appropriate HTTP headers for an Excel file download
    header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    header('Content-Disposition: attachment;filename="leads_import_template.xlsx"');
    header('Cache-Control: max-age=0');

    // Create the writer and save the file directly to the browser's output stream
    $writer = IOFactory::createWriter($spreadsheet, 'Xlsx');
    $writer->save('php://output');
    exit(); // IMPORTANT: Stop script execution to prevent any other HTML from being sent
}



$action_message = '';
if (isset($_GET['logout'])) {

    // --- START: RELIABLE LOGOUT LOGIC ---
    $log_id_to_update = 0;

    // Prioritize the ID from the URL, which is sent by the auto-logout script.
    if (isset($_GET['log_id']) && is_numeric($_GET['log_id'])) {
        $log_id_to_update = (int)$_GET['log_id'];
    }
    // Fallback to the session ID for manual logout clicks.
    elseif (isset($_SESSION['login_log_id'])) {
        $log_id_to_update = (int)$_SESSION['login_log_id'];
    }

    // If we have a valid ID, update the database record.
    if ($log_id_to_update > 0) {
        $logout_stmt = $conn->prepare("UPDATE login_logs SET logout_time = NOW() WHERE id = ?");
        $logout_stmt->bind_param("i", $log_id_to_update);
        $logout_stmt->execute();
        $logout_stmt->close();
    }
    // --- END: RELIABLE LOGOUT LOGIC ---

    session_destroy();
    header("Location: index.php?message=" . urlencode("You have been logged out."));
    exit();
}

// MODIFIED: Import handler now saves the source filename and redirects to the new batch view
// =================================================================
// ===== START: MODIFIED IMPORT HANDLER WITH DUPLICATE CHECK =======
// =================================================================
if (isset($_POST['import'])) {
    if (isset($_FILES['file']) && $_FILES['file']['size'] > 0) {
        $importer_id = $_SESSION['user_id'];
        $importer_role = $_SESSION['role'];
        $assign_to_user_id = $importer_id;
        $assignee_username = $_SESSION['username'];

        if (($importer_role === 'admin' || $importer_role === 'manager') && !empty($_POST['import_for_user_id'])) {
            $assign_to_user_id = intval($_POST['import_for_user_id']);
            $user_stmt = $conn->prepare("SELECT username FROM users WHERE id = ?");
            $user_stmt->bind_param("i", $assign_to_user_id);
            $user_stmt->execute();
            $user_result = $user_stmt->get_result();
            if ($user_row = $user_result->fetch_assoc()) {
                $assignee_username = $user_row['username'];
            }
            $user_stmt->close();
        }

        $file = $_FILES['file']['tmp_name'];
        $fileName = $_FILES['file']['name'];
        $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        $importedCount = 0;
        $skippedLeads = []; // Array to hold skipped duplicate leads

        $all_rows_data = [];

        // --- STEP 1: Read all data from the file ---
        try {
            if ($extension === 'csv') {
                $handle = fopen($file, "r");
                fgetcsv($handle); // Skip header
                while (($data = fgetcsv($handle, 1000, ",")) !== FALSE) {
                    $all_rows_data[] = $data;
                }
                fclose($handle);
            } else { // xlsx, xls
                $spreadsheet = IOFactory::load($file);
                $rows = $spreadsheet->getActiveSheet()->toArray();
                array_shift($rows); // Skip header
                $all_rows_data = $rows;
            }
        } catch (Exception $e) {
            $action_message = "Error reading file: " . $e->getMessage();
        }

        if (!empty($all_rows_data)) {
            // --- STEP 2: Process rows, checking for duplicates within this file only ---
            $phones_in_this_file = []; // Use a map to track phone numbers encountered so far
            $insert_stmt = $conn->prepare("INSERT INTO leads (user_id, imported_by, source_file, name, phone, status, followup_date, next_followup_date, requirement, source, feedback, service) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

            foreach ($all_rows_data as $data) {
                $phone_raw = preg_replace('/[^0-9]/', '', $data[1] ?? '');

                // Check if phone is missing or already seen in this file
                if (empty($phone_raw) || isset($phones_in_this_file[$phone_raw])) {
                    $skippedLeads[] = [
                        'name' => $data[0] ?? 'N/A',
                        'phone' => $data[1] ?? 'N/A',
                        'reason' => isset($phones_in_this_file[$phone_raw]) ? 'Duplicate in File' : 'Missing Phone Number'
                    ];
                    continue; // Skip to the next row
                }

                // If not a duplicate, proceed with insertion
                $name_db = encryptData($data[0] ?? '');
                $phone_db = encryptData($phone_raw);
                $status_db = encryptData($data[2] ?? 'Follow-up');
                $followup_date = !empty($data[3]) ? date('Y-m-d', strtotime($data[3])) : null;
                $next_followup_date = !empty($data[4]) ? date('Y-m-d', strtotime($data[4])) : null;
                $requirement_db = encryptData($data[5] ?? '');
                $source_db = encryptData($data[6] ?? '');
                $feedback_db = encryptData($data[7] ?? '');
                $service_db = encryptData($data[8] ?? '');

                $insert_stmt->bind_param("iissssssssss", $assign_to_user_id, $importer_id, $fileName, $name_db, $phone_db, $status_db, $followup_date, $next_followup_date, $requirement_db, $source_db, $feedback_db, $service_db);

                if ($insert_stmt->execute()) {
                    $importedCount++;
                    // Add the phone number to our tracking map for this file
                    $phones_in_this_file[$phone_raw] = true;
                }
            }
            $insert_stmt->close();
        }

        // --- STEP 3: Prepare final message and redirect ---
        $action_message = "Success! Imported $importedCount leads from '$fileName' for user '$assignee_username'.";
        if (count($skippedLeads) > 0) {
            $action_message .= " Skipped " . count($skippedLeads) . " duplicate or invalid records from the file.";
            $_SESSION['skipped_leads'] = $skippedLeads; // Store skipped leads in session
        }

        if ($importedCount > 0) {
            header("Location: index.php?view_batch=" . urlencode($fileName) . "&message=" . urlencode($action_message));
            exit();
        } elseif (!empty($skippedLeads)) {
            // If ALL leads were skipped, go back to the main page to show the skipped modal
            header("Location: index.php?message=" . urlencode($action_message));
            exit();
        } elseif (empty($action_message)) {
            $action_message = "Warning: File was empty or could not be read.";
        }
    } else {
        $action_message = "Error: Please choose a file to upload.";
    }
}
// =================================================================
// ===== END: MODIFIED IMPORT HANDLER ==============================
// =================================================================
if (isset($_POST['update_lead'])) {
    $lead_id = $_POST['lead_id'];
    $name = encryptData($_POST['name']);
    $phone = encryptData($_POST['phone']);
    $status = encryptData($_POST['status']);
    $followup_date = !empty($_POST['followup_date']) ? $_POST['followup_date'] : null;
    $next_followup_date = !empty($_POST['next_followup_date']) ? $_POST['next_followup_date'] : null;
    $requirement_value = ($_POST['requirement_select'] === 'Other' && !empty($_POST['other_requirement_text'])) ? $_POST['other_requirement_text'] : $_POST['requirement_select'];
    $requirement = encryptData($requirement_value);
    $communication_mode_value = ($_POST['communication_mode_select'] === 'Other' && !empty($_POST['other_communication_mode_text'])) ? $_POST['other_communication_mode_text'] : $_POST['communication_mode_select'];
    $communication_mode = encryptData($communication_mode_value);
    $source = encryptData($_POST['source']);
    $feedback = encryptData($_POST['feedback']);
    $service = encryptData($_POST['service']);
    $comments = encryptData($_POST['comments']);
    $checkStmt = $conn->prepare("SELECT user_id FROM leads WHERE id = ?");
    $checkStmt->bind_param("i", $lead_id);
    $checkStmt->execute();
    $result = $checkStmt->get_result();
    $lead = $result->fetch_assoc();
    if ($lead && ($_SESSION['role'] === 'admin' || $_SESSION['role'] === 'manager' || $lead['user_id'] == $_SESSION['user_id'])) {
        $stmt = $conn->prepare("UPDATE leads SET name=?, phone=?, status=?, followup_date=?, next_followup_date=?, requirement=?, communication_mode=?, source=?, feedback=?, service=?, comments=? WHERE id=?");
        $stmt->bind_param("sssssssssssi", $name, $phone, $status, $followup_date, $next_followup_date, $requirement, $communication_mode, $source, $feedback, $service, $comments, $lead_id);
        if ($stmt->execute()) {
            $action_message = "Lead updated successfully!";
            if (!empty($followup_date)) {
                $history_stmt = $conn->prepare("INSERT INTO followup_history (lead_id, user_id, followup_date) VALUES (?, ?, ?)");
                $history_stmt->bind_param("iis", $lead_id, $_SESSION['user_id'], $followup_date);
                $history_stmt->execute();
                $history_stmt->close();

                if (isset($_SESSION['login_log_id'])) {
                    $call_count_stmt = $conn->prepare("UPDATE login_logs SET call_count = call_count + 1 WHERE id = ?");
                    $call_count_stmt->bind_param("i", $_SESSION['login_log_id']);
                    $call_count_stmt->execute();
                    $call_count_stmt->close();
                }
            }
        } else {
            $action_message = "Error updating lead: " . $stmt->error;
        }
        $stmt->close();
    } else {
        $action_message = "Error: You do not have permission to edit this lead.";
    }
    $checkStmt->close();
}

if (isset($_POST['add_lead_to_batch'])) {
    $batch_name = $_POST['source_file'];
    $phone_raw = preg_replace('/[^0-9]/', '', $_POST['phone'] ?? '');

    // --- Duplicate Phone Check ---
    $is_duplicate = false;
    if (!empty($phone_raw)) {
        $encrypted_phone = encryptData($phone_raw);
        $check_stmt = $conn->prepare("SELECT id FROM leads WHERE phone = ?");
        $check_stmt->bind_param("s", $encrypted_phone);
        $check_stmt->execute();
        $check_stmt->store_result();
        if ($check_stmt->num_rows > 0) {
            $is_duplicate = true;
        }
        $check_stmt->close();
    } else {
        // Handle case where phone is empty, you might want to make it an error
        $action_message = "Error: Phone number is required.";
        header("Location: index.php?view_batch=" . urlencode($batch_name) . "&message=" . urlencode($action_message));
        exit();
    }

    if ($is_duplicate) {
        $action_message = "Error: A lead with the phone number '" . htmlspecialchars($_POST['phone']) . "' already exists.";
        header("Location: index.php?view_batch=" . urlencode($batch_name) . "&message=" . urlencode($action_message));
        exit();
    }

    // --- Proceed with inserting the new lead ---
    $name = encryptData($_POST['name']);
    $phone = encryptData($phone_raw); // Use cleaned and checked phone
    $status = encryptData($_POST['status']);
    $followup_date = !empty($_POST['followup_date']) ? $_POST['followup_date'] : null;
    $next_followup_date = !empty($_POST['next_followup_date']) ? $_POST['next_followup_date'] : null;

    $requirement_value = ($_POST['requirement_select'] === 'Other' && !empty($_POST['other_requirement_text'])) ? $_POST['other_requirement_text'] : $_POST['requirement_select'];
    $requirement = encryptData($requirement_value);

    $communication_mode_value = ($_POST['communication_mode_select'] === 'Other' && !empty($_POST['other_communication_mode_text'])) ? $_POST['other_communication_mode_text'] : $_POST['communication_mode_select'];
    $communication_mode = encryptData($communication_mode_value);

    $source = encryptData($_POST['source']);
    $feedback = encryptData($_POST['feedback']);
    $service = encryptData($_POST['service']);
    $comments = encryptData($_POST['comments']);

    // The new lead is assigned to the currently logged-in user
    $user_id = $_SESSION['user_id'];
    $importer_id = $_SESSION['user_id'];

    $stmt = $conn->prepare("INSERT INTO leads (user_id, imported_by, source_file, name, phone, status, followup_date, next_followup_date, requirement, communication_mode, source, feedback, service, comments) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("iissssssssssss", $user_id, $importer_id, $batch_name, $name, $phone, $status, $followup_date, $next_followup_date, $requirement, $communication_mode, $source, $feedback, $service, $comments);

    if ($stmt->execute()) {
        $action_message = "Success! New lead added to batch '" . htmlspecialchars($batch_name) . "'.";
    } else {
        $action_message = "Error adding lead: " . $stmt->error;
    }
    $stmt->close();

    header("Location: index.php?view_batch=" . urlencode($batch_name) . "&message=" . urlencode($action_message));
    exit();
}


if (isset($_GET['delete_id'])) {
    $lead_id_to_delete = intval($_GET['delete_id']);
    $current_user_id = $_SESSION['user_id'];
    $current_user_role = $_SESSION['role'];
    $can_delete = false;

    // First, get the owner and manager of the lead to be deleted
    $perm_stmt = $conn->prepare("SELECT l.user_id, u.manager_id FROM leads l JOIN users u ON l.user_id = u.id WHERE l.id = ?");
    $perm_stmt->bind_param("i", $lead_id_to_delete);
    $perm_stmt->execute();
    $result = $perm_stmt->get_result();
    $lead_to_check = $result->fetch_assoc();
    $perm_stmt->close();

    if ($lead_to_check) {
        // Rule 1: Admin can delete anything.
        if ($current_user_role === 'admin') {
            $can_delete = true;
        }
        // Rule 2: Manager can delete their own leads or leads of members they manage.
        elseif ($current_user_role === 'manager' && ($lead_to_check['user_id'] == $current_user_id || $lead_to_check['manager_id'] == $current_user_id)) {
            $can_delete = true;
        }
        // Rule 3: Member can only delete their own leads.
        elseif ($current_user_role === 'member' && $lead_to_check['user_id'] == $current_user_id) {
            $can_delete = true;
        }
    }

    if ($can_delete) {
        $stmt = $conn->prepare("DELETE FROM leads WHERE id = ?");
        $stmt->bind_param("i", $lead_id_to_delete);
        if ($stmt->execute()) {
            $action_message = "Success! Lead deleted.";
        } else {
            $action_message = "Error: Could not delete lead.";
        }
        $stmt->close();
    } else {
        $action_message = "Error: You do not have permission to delete this lead.";
    }
}

// NEW: Handler to delete an entire batch of leads
if (isset($_GET['delete_batch'])) {
    $batch_to_delete = $_GET['delete_batch'];
    $current_user_role = $_SESSION['role'];

    // Only allow Admin or Manager to delete batches
    if ($current_user_role === 'admin' || $current_user_role === 'manager') {
        $stmt = $conn->prepare("DELETE FROM leads WHERE source_file = ?");
        $stmt->bind_param("s", $batch_to_delete);

        if ($stmt->execute()) {
            $action_message = "Success! Batch '" . htmlspecialchars($batch_to_delete) . "' and all its leads have been deleted.";
        } else {
            $action_message = "Error: Could not delete the batch.";
        }
        $stmt->close();
    } else {
        $action_message = "Error: You do not have permission to delete batches.";
    }
    // Redirect to clear the GET parameter and show the message on the main batch list page
    header("Location: index.php?message=" . urlencode($action_message));
    exit();
}

if (isset($_POST['generate_report'])) {
    // MODIFIED: Only allow 'admin' role to generate the Excel report.
    if ($_SESSION['role'] === 'admin') {
        $report_user_ids_raw = $_POST['report_users'] ?? [];
        $start_date = $_POST['start_date'] ?? '';
        $end_date = $_POST['end_date'] ?? '';
        $batch_file_filter = $_POST['batch_file'] ?? '';

        if (empty($report_user_ids_raw) || empty($start_date) || empty($end_date)) {
            $action_message = "Warning: Please select a user and a date range to generate a report.";
        } else {
            // NOTE: The "team" logic is now only relevant for Admins viewing a Manager's team
            // but we can keep it for consistency. It won't be used by managers anymore.
            $report_user_ids = [];
            if ($report_user_ids_raw[0] === 'team') {
                // This part of the logic might need adjustment if an admin selects a manager and then "team"
                // For now, it defaults to the logged-in admin's "team", which is empty.
                // A better approach is to simply get all users. Let's adjust this slightly.
                // If "team" is selected, we'll assume it means all users for an admin.
                $all_users_stmt = $conn->query("SELECT id FROM users");
                while ($user = $all_users_stmt->fetch_assoc()) {
                    $report_user_ids[] = $user['id'];
                }
            } else {
                $report_user_ids = array_map('intval', $report_user_ids_raw);
            }

            $id_list = implode(',', $report_user_ids);
            $params = [$start_date, $end_date];
            $types = "ss";
            $sql = "SELECT l.*, u.username FROM leads l JOIN users u ON l.user_id = u.id WHERE l.user_id IN ($id_list) AND DATE(l.created_at) BETWEEN ? AND ?";

            // Conditionally add the batch filter
            if (!empty($batch_file_filter)) {
                $sql .= " AND l.source_file = ?";
                $params[] = $batch_file_filter;
                $types .= "s";
            }

            $sql .= " ORDER BY u.username, l.id DESC";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param($types, ...$params);
            $stmt->execute();
            $result = $stmt->get_result();

            $spreadsheet = new Spreadsheet();
            $sheet = $spreadsheet->getActiveSheet();
            $sheet->setTitle('Leads Report');
            $headers = ['Lead ID', 'Assigned To', 'Name', 'Phone', 'Status', 'Requirement', 'Source', 'Service', 'Feedback', 'Comments', 'Follow-up Date', 'Next Follow-up Date', 'Created At'];
            $sheet->fromArray($headers, NULL, 'A1');
            $rowIndex = 2;
            while ($row = $result->fetch_assoc()) {
                $rowData = [
                    $row['id'],
                    $row['username'],
                    decryptData($row['name']),
                    decryptData($row['phone']), // Exporting raw, unformatted phone number
                    decryptData($row['status']),
                    decryptData($row['requirement']),
                    decryptData($row['source']),
                    decryptData($row['service']),
                    decryptData($row['feedback']),
                    decryptData($row['comments']),
                    $row['followup_date'],
                    $row['next_followup_date'],
                    $row['created_at']
                ];
                $sheet->fromArray($rowData, NULL, 'A' . $rowIndex);
                $rowIndex++;
            }
            foreach (range('A', 'M') as $columnID) {
                $sheet->getColumnDimension($columnID)->setAutoSize(true);
            }
            header('Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
            header('Content-Disposition: attachment;filename="leads_report_' . date('Y-m-d') . '.xlsx"');
            header('Cache-Control: max-age=0');
            $writer = IOFactory::createWriter($spreadsheet, 'Xlsx');
            $writer->save('php://output');
            exit();
        }
    }
}

if (isset($_POST['save_user'])) {
    if ($_SESSION['role'] === 'admin') {
        $user_id = $_POST['user_id'] ?? null;
        $username = $_POST['username'];
        $email = $_POST['email'];
        $role = $_POST['role'];
        $password = $_POST['password'];
        $confirm_password = $_POST['confirm_password'];

        // =================== MODIFIED LOGIC: CAPTURE MANAGER ID ===================
        // If the role is 'member' and a manager is selected, use that ID. Otherwise, it's NULL.
        $manager_id = ($role === 'member' && !empty($_POST['manager_id'])) ? intval($_POST['manager_id']) : NULL;
        // =========================================================================

        if ($password !== $confirm_password) {
            $action_message = "Error: Passwords do not match.";
        } else {
            // Logic for Adding a New User
            if (empty($user_id)) {
                if (empty($password)) {
                    $action_message = "Error: Password is required for a new user.";
                } else {
                    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                    // MODIFIED INSERT: Include manager_id
                    $stmt = $conn->prepare("INSERT INTO users (username, email, password, role, manager_id) VALUES (?, ?, ?, ?, ?)");
                    $stmt->bind_param("ssssi", $username, $email, $hashed_password, $role, $manager_id);
                    if ($stmt->execute()) {
                        $action_message = "Success! New user added.";
                    } else {
                        $action_message = "Error: Could not add user. " . $stmt->error;
                    }
                    $stmt->close();
                }
            }
            // Logic for Updating an Existing User
            else {
                if (!empty($password)) {
                    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
                    // MODIFIED UPDATE with password: Include manager_id
                    $stmt = $conn->prepare("UPDATE users SET username=?, email=?, password=?, role=?, manager_id=? WHERE id=?");
                    $stmt->bind_param("ssssii", $username, $email, $hashed_password, $role, $manager_id, $user_id);
                } else {
                    // MODIFIED UPDATE without password: Include manager_id
                    $stmt = $conn->prepare("UPDATE users SET username=?, email=?, role=?, manager_id=? WHERE id=?");
                    $stmt->bind_param("sssii", $username, $email, $role, $manager_id, $user_id);
                }

                if ($stmt->execute()) {
                    $action_message = "Success! User updated.";
                } else {
                    $action_message = "Error: Could not update user. " . $stmt->error;
                }
                $stmt->close();
            }
        }
    } else {
        $action_message = "Error: Permission denied.";
    }
}

// --- Handler to Delete a User ---
if (isset($_GET['delete_user_id'])) {
    if ($_SESSION['role'] === 'admin') {
        $user_id_to_delete = intval($_GET['delete_user_id']);

        // Prevent admin from deleting themselves
        if ($user_id_to_delete == $_SESSION['user_id']) {
            $action_message = "Error: You cannot delete your own account.";
        } else {
            // Optional: Handle leads of the deleted user. Here we just delete the user.
            $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
            $stmt->bind_param("i", $user_id_to_delete);
            if ($stmt->execute()) {
                $action_message = "Success! User deleted.";
            } else {
                $action_message = "Error: Could not delete user.";
            }
            $stmt->close();
        }
    } else {
        $action_message = "Error: Permission denied.";
    }
}


function handle_add($table, $name, $color = null)
{
    global $conn, $action_message;
    if ($_SESSION['role'] !== 'admin') {
        $action_message = "Error: Permission denied.";
        return;
    }
    if ($color) {
        $stmt = $conn->prepare("INSERT INTO $table (name, color) VALUES (?, ?)");
        $stmt->bind_param("ss", $name, $color);
    } else {
        $stmt = $conn->prepare("INSERT INTO $table (name) VALUES (?)");
        $stmt->bind_param("s", $name);
    }
    if ($stmt->execute()) {
        $action_message = "Success! New option added.";
    } else {
        $action_message = "Error: Could not add option. " . $stmt->error;
    }
    $stmt->close();
}

function handle_delete($table, $id)
{
    global $conn, $action_message;
    if ($_SESSION['role'] !== 'admin') {
        $action_message = "Error: Permission denied.";
        return;
    }
    $stmt = $conn->prepare("DELETE FROM $table WHERE id = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        $action_message = "Success! Option deleted.";
    } else {
        $action_message = "Error: Could not delete option.";
    }
    $stmt->close();
}

if (isset($_POST['add_status'])) {
    handle_add('statuses', $_POST['name'], $_POST['color']);
}
if (isset($_GET['delete_status_id'])) {
    handle_delete('statuses', $_GET['delete_status_id']);
}
if (isset($_POST['add_requirement'])) {
    handle_add('requirements', $_POST['name']);
}
if (isset($_GET['delete_requirement_id'])) {
    handle_delete('requirements', $_GET['delete_requirement_id']);
}
if (isset($_POST['add_comm_mode'])) {
    handle_add('communication_modes', $_POST['name']);
}
if (isset($_GET['delete_comm_mode_id'])) {
    handle_delete('communication_modes', $_GET['delete_comm_mode_id']);
}

// =================================================================
// LOGIN & OTP VERIFICATION FLOW
// =================================================================
if (!isset($_SESSION['otp_verified'])) {
    $login_error = '';

    // --- STEP 2: OTP VERIFICATION (This part is mostly unchanged) ---
    // User is submitting the OTP they received
    if (isset($_POST['verify_otp'])) {
        if (isset($_SESSION['otp'], $_POST['otp']) && $_POST['otp'] == $_SESSION['otp']) {
            $_SESSION['otp_verified'] = true;
            $_SESSION['last_activity'] = time();
            $username = $_SESSION['otp_user']; // We get the username stored from Step 1

            // Log the user in fully
            $stmt = $conn->prepare("SELECT id, role, username FROM users WHERE username=?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $stmt->bind_result($userId, $role, $uname);
            $stmt->fetch();
            $stmt->close();

            $_SESSION['user_id'] = $userId;
            $_SESSION['role'] = $role;
            $_SESSION['username'] = $uname;

            // Log the login event
            $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
            $login_log_stmt = $conn->prepare("INSERT INTO login_logs (user_id, username, login_time, ip_address) VALUES (?, ?, NOW(), ?)");
            $login_log_stmt->bind_param("iss", $userId, $uname, $ip_address);
            $login_log_stmt->execute();
            $_SESSION['login_log_id'] = $login_log_stmt->insert_id;

            $login_log_stmt->close();

            // Cleanup and redirect
            unset($_SESSION['otp'], $_SESSION['otp_user']);
            header("Location: index.php");
            exit();
        } else {
            // If OTP is wrong, show the OTP page again with an error
            $login_error = "Incorrect OTP. Please try again.";
            $_SESSION['otp_requested'] = true; // Keep the user on the OTP page
        }
    }

    // --- STEP 1: INITIAL LOGIN ATTEMPT (Email + Password) ---
    // User is submitting the email and password form for the first time
    if (isset($_POST['login_attempt'])) {
        $email_to_check = $_POST['email'];
        // CAPTURE THE PASSWORD FROM THE FORM
        $password_attempt = $_POST['password'];

        // Find the user by email to get their username, ID, and HASHED PASSWORD
        $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE email=?");
        $stmt->bind_param("s", $email_to_check);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();

            // ================== NEW PASSWORD CHECK ==================
            if (password_verify($password_attempt, $user['password'])) {
                // Password is CORRECT, proceed with OTP

                // Generate and send OTP
                $otp = rand(100000, 999999);
                $_SESSION['otp'] = $otp;
                $_SESSION['otp_user'] = $user['username']; // CRITICAL: Store the USERNAME for the next step
                $_SESSION['otp_requested'] = true;       // Flag to show the OTP form

                // echo "<pre>DEMO OTP: $otp</pre>"; 
                sendOTP($email_to_check, $otp);
                // The script will now fall through to the logic below that displays the OTP form

            } else {
                // Password is WRONG
                $login_error = "Invalid email or password.";
            }
            // =======================================================

        } else {
            // No user found with that email
            $login_error = "Invalid email or password."; // Use a generic message for security
        }
        $stmt->close();
    }

    // --- DISPLAY LOGIC: Decide which form to show ---

    // If an OTP has been requested (either just now, or on a failed attempt), show the OTP form.
    if (isset($_SESSION['otp_requested'])) {
        echo '<!DOCTYPE html><html><head><title>Verify OTP</title><style>body{font-family:sans-serif;background:#f4f4f4;display:flex;justify-content:center;align-items:center;height:100vh}.login-box{background:white;padding:40px;border-radius:8px;box-shadow:0 4px 10px rgba(0,0,0,0.1);text-align:center;width:320px}input{padding:10px;margin:10px 0;width:100%;box-sizing:border-box}button{background:#007bff;color:white;padding:10px 15px;border:none;border-radius:5px;cursor:pointer;width:100%}.error{color:red;}</style></head><body>';
        echo '<div class="login-box"><h2>Verify OTP</h2><p>An OTP has been sent to your registered email.</p>';
        if ($login_error) echo "<p class='error'>$login_error</p>";
        echo '<form method="POST" action="index.php"><input type="text" name="otp" placeholder="Enter OTP" required autofocus><br><button type="submit" name="verify_otp">Verify OTP</button></form></div>';
        echo '</body></html>';
        exit();
    }

    // Otherwise, show the initial Email and Password login form.
    echo '<!DOCTYPE html><html><head><title>Login</title><style>body{font-family:sans-serif;background:#f4f4f4;display:flex;justify-content:center;align-items:center;height:100vh}.login-box{background:white;padding:40px;border-radius:8px;box-shadow:0 4px 10px rgba(0,0,0,0.1);text-align:center;width:320px}input{padding:10px;margin:10px 0;width:100%;box-sizing:border-box}button{background:#007bff;color:white;padding:10px 15px;border:none;border-radius:5px;cursor:pointer;width:100%}.error{color:red;}.form-group{text-align:left;margin-bottom:15px;}</style></head><body>';
    echo '<div class="login-box"><h2>CRM Login</h2>';
    if ($login_error) echo "<p class='error'>$login_error</p>";
    echo '<form method="POST" action="index.php">';
    echo '<div class="form-group"><label for="email">Email Address:</label><input type="email" id="email" name="email" required></div>';
    echo '<div class="form-group"><label for="password">Password:</label><input type="password" id="password" name="password" required></div>';
    echo '<button type="submit" name="login_attempt">Login</button>';
    echo '</form></div>';
    echo '</body></html>';
    exit();
}

// =================================================================
// MAIN APPLICATION DATA FETCH
// =================================================================
$edit_lead_data = null;
$view_lead_data = null;
$edit_user_data = null; // NEW: For the user edit form
$current_mode = 'list'; // Default mode is now the batch list
if (isset($_GET['message'])) {
    $action_message = $_GET['message'];
}
if (isset($_GET['edit_id'])) {
    $current_mode = 'edit';
    $edit_id = $_GET['edit_id'];
    $stmt = $conn->prepare("SELECT * FROM leads WHERE id = ?");
    $stmt->bind_param("i", $edit_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        $edit_lead_data = $result->fetch_assoc();
        if ($_SESSION['role'] !== 'admin' && $_SESSION['role'] !== 'manager' && $edit_lead_data['user_id'] != $_SESSION['user_id']) {
            $edit_lead_data = null;
            $action_message = "Error: You do not have permission to edit this lead.";
            $current_mode = 'list';
        }
    }
    $stmt->close();
} elseif (isset($_GET['view_id'])) {
    $current_mode = 'view';
    $view_id = $_GET['view_id'];
    $stmt = $conn->prepare("SELECT l.*, u.username FROM leads l JOIN users u ON l.user_id = u.id WHERE l.id = ?");
    $stmt->bind_param("i", $view_id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows > 0) {
        $view_lead_data = $result->fetch_assoc();
        if ($_SESSION['role'] !== 'admin' && $_SESSION['role'] !== 'manager' && $view_lead_data['user_id'] != $_SESSION['user_id']) {
            $view_lead_data = null;
            $action_message = "Error: You do not have permission to view this lead.";
            $current_mode = 'list';
        }
    }
    $stmt->close();
} elseif (isset($_GET['view_logs']) && ($_SESSION['role'] === 'admin' || $_SESSION['role'] === 'manager')) { // MODIFIED PERMISSION
    $current_mode = 'logs';
} elseif (isset($_GET['reports'])) {
    $current_mode = 'reports';
}
// NEW: Route for the User Management page
elseif (isset($_GET['manage_users']) && $_SESSION['role'] === 'admin') {
    $current_mode = 'manage_users';
    if (isset($_GET['edit_user_id'])) {
        $user_id_to_edit = intval($_GET['edit_user_id']);
        $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id_to_edit);
        $stmt->execute();
        $result = $stmt->get_result();
        $edit_user_data = $result->fetch_assoc();
        $stmt->close();
    }
} elseif (isset($_GET['manage_options']) && $_SESSION['role'] === 'admin') {
    $current_mode = 'manage_options';
}
// Note: $batch_filter is no longer needed, we use view_batch instead.
$today_reminders_count = 0;
$missed_reminders_count = 0;
$today = date('Y-m-d');
$seven_days_ago = date('Y-m-d', strtotime('-7 days'));
$role = $_SESSION['role'];
$user_id = $_SESSION['user_id'];

// Base SQL query
$count_sql = "SELECT 
    SUM(CASE WHEN l.next_followup_date = ? THEN 1 ELSE 0 END) as today_count,
    SUM(CASE WHEN l.next_followup_date >= ? AND l.next_followup_date < ? THEN 1 ELSE 0 END) as missed_count
FROM leads l";
$params = [$today, $seven_days_ago, $today];
$types = "sss";

// Append role-specific conditions
if ($role === 'manager') {
    $count_sql .= " JOIN users u ON l.user_id = u.id WHERE (l.user_id = ? OR u.manager_id = ?)";
    $params[] = $user_id;
    $params[] = $user_id;
    $types .= "ii";
} elseif ($role === 'member') {
    $count_sql .= " WHERE l.user_id = ?";
    $params[] = $user_id;
    $types .= "i";
}
// Admin requires no extra WHERE clause, so it correctly counts all leads.

$count_stmt = $conn->prepare($count_sql);
$count_stmt->bind_param($types, ...$params);
$count_stmt->execute();
$count_result = $count_stmt->get_result()->fetch_assoc();
if ($count_result) {
    $today_reminders_count = $count_result['today_count'] ?? 0;
    $missed_reminders_count = $count_result['missed_count'] ?? 0;
}
$count_stmt->close();
?>
<!DOCTYPE html>
<html>

<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CRM Dashboard</title>
    <link rel="icon" type="image/png" href="favicon.png"> <!-- ADD THIS LINE -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
    <style>
        /* CSS is unchanged, but I've added a couple of minor styles for clarity */
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            margin: 0;
            background-color: #f8f9fa;
        }

        .container {
            max-width: 1400px;
            margin: 20px auto;
            padding: 20px;
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }

        h2,
        h3 {
            color: #333;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        th,
        td {
            padding: 12px 15px;
            border: 1px solid #ddd;
            text-align: left;
            vertical-align: middle;
        }

        th {
            background-color: #f2f2f2;
            font-weight: 600;
        }

        tr:nth-child(even) {
            background-color: #f9f9f9;
        }

        tr:hover {
            background-color: #f1f1f1;
        }

        form {
            margin-bottom: 20px;
            padding: 15px;
            background-color: #fdfdfd;
            border: 1px solid #eee;
            border-radius: 5px;
        }

        input[type="file"],
        input[type="text"],
        input[type="date"],
        select,
        textarea {
            padding: 8px;
            margin-right: 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
        }

        textarea {
            width: 100%;
        }

        button,
        a.button-link {
            display: inline-block;
            padding: 9px 15px;
            background-color: #28a745;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            text-decoration: none;
            font-size: 14px;
            margin-right: 5px;
            vertical-align: middle;
        }

        button[type="submit"] {
            background-color: #007bff;
        }

        a.button-link.edit {
            background-color: #ffc107;
            color: #212529;
        }

        a.button-link.back {
            background-color: #6c757d;
        }

        a.button-link.delete {
            background-color: #dc3545;
        }

        a.button-link.reports {
            background-color: #6610f2;
        }

        a.button-link.logs {
            background-color: #343a40;
        }

        .view-button {
            padding: 5px 12px;
            background-color: #17a2b8;
            color: white;
            border-radius: 4px;
            text-decoration: none;
            font-size: 13px;
        }

        .header {
            background: #343a40;
            color: white;
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header a {
            color: #fff;
            text-decoration: none;
        }

        .message {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }

        .message.success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .message.error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .message.warning {
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeeba;
        }

        .form-container,
        .view-container,
        .logs-container {
            padding: 20px;
            background-color: #e9ecef;
            border-radius: 8px;
            margin-top: 20px;
        }

        .view-container p {
            margin: 0 0 12px 0;
            font-size: 16px;
        }

        .view-container strong {
            display: inline-block;
            width: 180px;
            color: #495057;
        }

        .form-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }

        .lead-update-dropdown,
        .lead-update-input {
            width: 100%;
            padding: 6px;
            border-radius: 4px;
            border: 1px solid #ccc;
            background-color: #fff;
            transition: background-color 0.3s;
            box-sizing: border-box;
        }

        .status-dropdown {
            color: white;
            font-weight: bold;
            text-shadow: 1px 1px 1px rgba(0, 0, 0, 0.2);
        }

        .password-wrapper {
            position: relative;
        }

        .password-wrapper input {
            padding-right: 40px;
        }

        .password-toggle {
            position: absolute;
            top: 50%;
            right: 10px;
            transform: translateY(-50%);
            cursor: pointer;
            color: #666;
            font-size: 1rem;
        }


        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.6);
            display: none;
            /* Initially hidden */
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }

        .modal-content {
            background: #fff;
            padding: 30px;
            border-radius: 8px;
            width: 500px;
            max-width: 90%;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
            position: relative;
        }

        .modal-close {
            position: absolute;
            top: 10px;
            right: 15px;
            font-size: 1.5rem;
            font-weight: bold;
            color: #666;
            cursor: pointer;
        }

        .modal-content h3 {
            margin-top: 0;
            border-bottom: 1px solid #ddd;
            padding-bottom: 15px;
        }

        #user_selection_div {
            display: none;
            /* Hidden by default */
            margin-top: 15px;
        }

        #import_for_user_id {
            width: 100%;
            padding: 8px;
        }

        .history-icon {
            margin-left: 8px;
            color: #007bff;
            cursor: pointer;
            font-size: 0.9em;
        }

        .popover {
            position: absolute;
            background-color: #fff;
            border: 1px solid #ccc;
            border-radius: 5px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
            padding: 10px;
            z-index: 1001;
            display: none;
            /* Initially hidden */
            width: 250px;
        }

        .popover h4 {
            margin: 0 0 10px 0;
            padding-bottom: 5px;
            border-bottom: 1px solid #eee;
            font-size: 14px;
        }

        .popover ul {
            margin: 0;
            padding: 0 0 0 15px;
            list-style-type: none;
        }

        .popover li {
            font-size: 13px;
            margin-bottom: 5px;
        }

        .popover li strong {
            color: #333;
        }

        .filter-form {
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-bottom: 20px;
        }

        .filter-form label {
            font-weight: 500;
        }


        /* NEW: Styles for the Reminder Banner */
        @keyframes blink-animation {
            50% {
                background-color: #ffc107;
            }
        }

        .reminder-banner {
            padding: 15px;
            margin-bottom: 20px;
            background-color: #fff3cd;
            color: #856404;
            border: 1px solid #ffeeba;
            border-radius: 5px;
            font-weight: bold;
            animation: blink-animation 2s infinite;
        }

        .reminder-banner i {
            margin-right: 10px;
        }

        .header h1 {
            margin: 0;
            line-height: 1;
            /* Aligns image better */
        }

        .header-logo {
            max-height: 40px;
            /* Adjust as needed */
            width: auto;
        }

        .main-footer {
            text-align: center;
            padding: 20px;
            margin-top: 30px;
            color: #6c757d;
            border-top: 1px solid #e7e7e7;
            font-size: 0.9em;
        }

        .company-name {
            color: #28a745;
            /* Green color */
            font-weight: bold;
        }


        .options-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 30px;
        }

        .options-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            background-color: #fdfdfd;
        }

        .options-card h4 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }

        .options-list {
            list-style: none;
            padding: 0;
            max-height: 200px;
            overflow-y: auto;
        }

        .options-list li {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px;
            border-bottom: 1px solid #f0f0f0;
        }

        .options-list li:last-child {
            border-bottom: none;
        }

        .options-list .delete-option {
            color: #dc3545;
            text-decoration: none;
            font-size: 0.9em;
        }

        .searchable-dropdown {
            position: relative;
        }

        .searchable-dropdown-input {
            width: 100%;
            padding: 6px;
            box-sizing: border-box;
            border: 1px solid #ccc;
            border-radius: 4px;
        }

        .searchable-dropdown-options {
            display: none;
            /* Hidden by default */
            position: absolute;
            top: 100%;
            left: 0;
            width: 100%;
            max-height: 200px;
            overflow-y: auto;
            border: 1px solid #ccc;
            border-top: none;
            background-color: #fff;
            z-index: 1010;
            /* Ensure it appears above other elements */
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .searchable-dropdown-options div {
            padding: 8px 10px;
            cursor: pointer;
        }

        .searchable-dropdown-options div:hover {
            background-color: #f1f1f1;
        }


        /* ... existing CSS ... */

        .skipped-leads-table {
            width: 100%;
            margin-top: 15px;
            border-collapse: collapse;
        }

        .skipped-leads-table th,
        .skipped-leads-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }

        .skipped-leads-table th {
            background-color: #f2f2f2;
        }

        .skipped-leads-container {
            max-height: 300px;
            overflow-y: auto;
        }

        /* ... existing CSS ... */

        .pagination-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 20px;
        }

        .pagination {
            list-style: none;
            padding: 0;
            margin: 0;
            display: flex;
            gap: 5px;
        }

        .pagination li a,
        .pagination li span {
            display: block;
            padding: 8px 12px;
            text-decoration: none;
            color: #007bff;
            background: #fff;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        .pagination li a:hover {
            background: #f0f0f0;
        }

        .pagination li.active span {
            background: #007bff;
            color: #fff;
            border-color: #007bff;
        }

        .pagination li.disabled span {
            color: #6c757d;
            background-color: #e9ecef;
            cursor: not-allowed;
        }

        .pagination-summary {
            color: #6c757d;
            font-size: 0.9em;
        }

        @media (max-width: 992px) {
            .container {
                max-width: 95%;
                padding: 15px;
            }

            .form-grid {
                grid-template-columns: 1fr;
                /* Stack form fields into a single column */
            }

            .header {
                flex-direction: column;
                gap: 10px;
                padding: 15px;
            }

            .header h1 {
                margin-bottom: 10px;
            }
        }

        /* --- For Mobile Phones --- */
        @media (max-width: 768px) {

            .filter-form,
            .actions-bar {
                flex-direction: column;
                align-items: stretch;
                /* Make items full-width */
            }

            .filter-form>div,
            .filter-form button,
            .actions-bar a,
            .actions-bar button {
                width: 100%;
                box-sizing: border-box;
                margin-right: 0;
                margin-bottom: 10px;
            }

            .pagination-container {
                flex-direction: column;
                gap: 10px;
            }

            .pagination {
                flex-wrap: wrap;
                justify-content: center;
            }

            /* --- Making tables horizontally scrollable --- */
            /* This is the key to handling large tables on small screens */
            .table-responsive-wrapper {
                overflow-x: auto;
                -webkit-overflow-scrolling: touch;
                /* Smooth scrolling on iOS */
            }

            /* On mobile, we hide some less critical columns by default */
            /* Add the 'mobile-hide' class to TH and TD tags you want to hide */
            .mobile-hide {
                display: none;
            }

            /* Adjust padding for more space */
            th,
            td {
                padding: 8px 10px;
            }
        }
    </style>
</head>

<body>

    <div class="header">
        <h1><a href="index.php"><img src="logo_new.svg" alt="CRM Logo" class="header-logo"></a></h1>
        <div>
            <span>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?> (<?php echo htmlspecialchars($_SESSION['role']); ?>)</span> |
            <a href="?logout=true">Logout</a>
        </div>
    </div>

    <div class="container">
        <?php if ($today_reminders_count > 0 || $missed_reminders_count > 0): ?>
            <div class="reminder-banner">
                <i class="fa-solid fa-bell"></i>
                <strong>REMINDERS:</strong>
                You have <strong><?php echo $today_reminders_count; ?></strong> follow-ups for today and <strong><?php echo $missed_reminders_count; ?></strong> missed follow-ups.
                <a href="reminders.php" class="button-link" style="float: right; margin-top: -5px;">View Details</a>
            </div>
        <?php endif; ?>
        <?php if ($action_message): ?>
            <div class="message <?php echo strpos(strtolower($action_message), 'success') !== false ? 'success' : (strpos(strtolower($action_message), 'error') !== false ? 'error' : 'warning'); ?>">
                <?php echo htmlspecialchars($action_message); ?>
            </div>
        <?php endif; ?>

        <?php if ($current_mode === 'view' && $view_lead_data): ?><!-- View Block is Correct -->
            <div class="view-container">
                <h3>Lead Details</h3>
                <p><strong>Name:</strong> <?php echo htmlspecialchars(decryptData($view_lead_data['name'])); ?></p>
                <p><strong>Phone:</strong> <?php echo htmlspecialchars(formatPhoneNumber(decryptData($view_lead_data['phone']))); ?></p>
                <p><strong>Status:</strong> <?php echo htmlspecialchars(decryptData($view_lead_data['status'])); ?></p>
                <p><strong>Follow-up Date:</strong> <?php echo $view_lead_data['followup_date'] ? date('d-m-Y', strtotime($view_lead_data['followup_date'])) : 'N/A'; ?></p>
                <p><strong>Next Follow-up Date:</strong> <?php echo $view_lead_data['next_followup_date'] ? date('d-m-Y', strtotime($view_lead_data['next_followup_date'])) : 'N/A'; ?></p>
                <p><strong>Requirement:</strong> <?php echo htmlspecialchars(decryptData($view_lead_data['requirement'])); ?></p>
                <p><strong>Mode of Communication:</strong> <?php echo htmlspecialchars(decryptData($view_lead_data['communication_mode'])); ?></p>
                <p><strong>Source:</strong> <?php echo htmlspecialchars(decryptData($view_lead_data['source'])); ?></p>
                <p><strong>Service:</strong> <?php echo nl2br(htmlspecialchars(decryptData($view_lead_data['service']))); ?></p>
                <p><strong>Feedback:</strong> <?php echo nl2br(htmlspecialchars(decryptData($view_lead_data['feedback']))); ?></p>
                <p><strong>Comments:</strong> <?php echo nl2br(htmlspecialchars(decryptData($view_lead_data['comments']))); ?></p>
                <p><strong>Assigned To:</strong> <?php echo htmlspecialchars($view_lead_data['username']); ?></p>
                <br>
                <?php
                // NEW: Logic to determine the correct "back" link
                $back_link = isset($_GET['from']) && $_GET['from'] === 'reminders' ? 'reminders.php' : 'index.php';
                ?>
                <a href="?edit_id=<?php echo $view_lead_data['id']; ?>" class="button-link edit">Edit This Lead</a>
                <a href="<?php echo $back_link; ?>" class="button-link back">Back to List</a>
            </div>
        <?php elseif ($current_mode === 'edit' && $edit_lead_data): ?><!-- Edit Block is Correct -->
            <?php
            $currentRequirement = decryptData($edit_lead_data['requirement']);
            $is_other_requirement_edit = !in_array($currentRequirement, $requirement_options) && !empty($currentRequirement);
            $currentCommMode = decryptData($edit_lead_data['communication_mode']);
            $is_other_comm_mode_edit = !in_array($currentCommMode, $communication_mode_options) && !empty($currentCommMode);
            ?>
            <div class="form-container">
                <h3>Edit Lead</h3>
                <form method="POST" action="index.php">
                    <input type="hidden" name="lead_id" value="<?php echo $edit_lead_data['id']; ?>">
                    <div class="form-grid">
                        <div>
                            <label for="name">Name:</label><br>
                            <input type="text" id="name" name="name" value="<?php echo htmlspecialchars(decryptData($edit_lead_data['name'])); ?>" required style="width:100%;">
                        </div>
                        <div>
                            <label for="phone">Phone:</label><br>
                            <input type="text" id="phone" name="phone" value="<?php echo htmlspecialchars(formatPhoneNumber(decryptData($edit_lead_data['phone']))); ?>" required style="width:100%;">
                        </div>
                        <div>
                            <label for="status">Status:</label><br>
                            <select name="status" id="status" required style="width:100%;">
                                <?php
                                $currentStatus = decryptData($edit_lead_data['status']);
                                foreach ($status_options as $option => $color) {
                                    $selected = ($currentStatus == $option) ? 'selected' : '';
                                    echo "<option value=\"$option\" $selected>$option</option>";
                                }
                                ?>
                            </select>
                        </div>
                        <div>
                            <label for="followup_date">Follow-up Date:</label><br>
                            <input type="date" id="followup_date" name="followup_date" value="<?php echo $edit_lead_data['followup_date']; ?>" style="width:100%;">
                        </div>
                        <div>
                            <label for="next_followup_date">Next Follow-up Date:</label><br>
                            <input type="date" id="next_followup_date" name="next_followup_date" value="<?php echo $edit_lead_data['next_followup_date']; ?>" style="width:100%;">
                        </div>
                        <div>
                            <label for="source">Source:</label><br>
                            <input type="text" id="source" name="source" value="<?php echo htmlspecialchars(decryptData($edit_lead_data['source'])); ?>" style="width:100%;">
                        </div>
                        <div>
                            <label for="requirement_select">Requirement:</label><br>
                            <div class="searchable-dropdown">
                                <!-- The hidden select is what the form submits -->
                                <select name="requirement_select" id="requirement_edit_select" style="display:none;">
                                    <?php
                                    foreach ($requirement_options as $option) {
                                        if ($option === 'Other' && $is_other_requirement_edit) {
                                            echo "<option value=\"Other\" selected>Other</option>";
                                        } else {
                                            $selected = ($currentRequirement == $option) ? 'selected' : '';
                                            echo "<option value=\"$option\" $selected>$option</option>";
                                        }
                                    }
                                    ?>
                                </select>
                                <!-- The visible input for searching -->
                                <input type="text" class="searchable-dropdown-input" placeholder="Search or select..." value="<?php echo htmlspecialchars($currentRequirement); ?>">
                                <!-- The options list -->
                                <div class="searchable-dropdown-options">
                                    <?php
                                    foreach ($requirement_options as $option) {
                                        echo "<div data-value=\"$option\">$option</div>";
                                    }
                                    ?>
                                </div>
                            </div>
                            <!-- The "Other" text field logic remains -->
                            <input type="text" name="other_requirement_text" id="other_requirement_edit" placeholder="Specify other requirement" value="<?php echo $is_other_requirement_edit ? htmlspecialchars($currentRequirement) : ''; ?>" style="width:100%; margin-top: 5px; display: <?php echo $is_other_requirement_edit ? 'block' : 'none'; ?>;">
                        </div>
                        <div>
                            <label for="communication_mode_select">Mode of Communication:</label><br>
                            <select name="communication_mode_select" id="comm_mode_edit_select" style="width:100%;">
                                <?php
                                foreach ($communication_mode_options as $option) {
                                    if ($option === 'Other' && $is_other_comm_mode_edit) {
                                        echo "<option value=\"Other\" selected>Other</option>";
                                    } else {
                                        $selected = ($currentCommMode == $option) ? 'selected' : '';
                                        echo "<option value=\"$option\" $selected>$option</option>";
                                    }
                                }
                                ?>
                            </select>
                            <input type="text" name="other_communication_mode_text" id="other_comm_mode_edit" placeholder="Specify other mode" value="<?php echo $is_other_comm_mode_edit ? htmlspecialchars($currentCommMode) : ''; ?>" style="width:100%; margin-top: 5px; display: <?php echo $is_other_comm_mode_edit ? 'block' : 'none'; ?>;">
                        </div>
                    </div>
                    <div><br><label for="service">Service:</label><br><textarea name="service" id="service" rows="3"><?php echo htmlspecialchars(decryptData($edit_lead_data['service'])); ?></textarea></div>
                    <div><br><label for="feedback">Feedback:</label><br><textarea name="feedback" id="feedback" rows="3"><?php echo htmlspecialchars(decryptData($edit_lead_data['feedback'])); ?></textarea></div>
                    <div><br><label for="comments">Internal Comments:</label><br><textarea name="comments" id="comments" rows="3"><?php echo htmlspecialchars(decryptData($edit_lead_data['comments'])); ?></textarea></div>
                    <br>
                    <?php
                    // NEW: Logic to determine the correct "back" link
                    $back_link = isset($_GET['from']) && $_GET['from'] === 'reminders' ? 'reminders.php' : 'index.php';
                    ?>
                    <button type="submit" name="update_lead">Update Lead</button>
                    <a href="<?php echo $back_link; ?>" class="button-link back" style="margin-left: 10px;">Cancel</a>
                </form>
            </div>

        <?php elseif ($current_mode === 'logs'): ?>
            <div class="logs-container">
                <h3>User Login History
                    <a href="index.php" class="button-link back" style="float:right;">Back to Dashboard</a>
                </h3>
                <div class="table-responsive-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Login Time</th>
                                <th>Logout Time</th>
                                <th>Total Calls Made</th>
                                <th>IP Address</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            // =================================================================
                            // ===== START: MODIFIED LOGS QUERY ================================
                            // =================================================================

                            // Step 1: Get the main login log data
                            $per_page = 50;
                            $current_page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
                            $offset = ($current_page - 1) * $per_page;

                            // --- GET TOTAL COUNT ---
                            $total_logs = $conn->query("SELECT COUNT(id) as total FROM login_logs")->fetch_assoc()['total'];

                            // --- GET PAGINATED DATA ---
                            $log_stmt = $conn->prepare("SELECT id, user_id, username, login_time, logout_time, call_count, ip_address FROM login_logs ORDER BY login_time DESC LIMIT ? OFFSET ?");
                            $log_stmt->bind_param("ii", $per_page, $offset);
                            $log_stmt->execute();
                            $log_result = $log_stmt->get_result();
                            $login_logs = $log_result->fetch_all(MYSQLI_ASSOC);
                            $log_stmt->close();

                            // --- BATCH COUNT LOGIC (Remains the same) ---
                            $log_ids = array_column($login_logs, 'id');
                            $batch_counts = [];

                            if (!empty($log_ids)) {
                                $placeholders = implode(',', array_fill(0, count($log_ids), '?'));
                                $types = str_repeat('i', count($log_ids));

                                $batch_sql = "SELECT 
                                          ll.id as log_id,
                                          l.source_file, 
                                          COUNT(fh.id) as batch_call_count
                                      FROM 
                                          followup_history fh
                                      JOIN 
                                          leads l ON fh.lead_id = l.id
                                      JOIN
                                          login_logs ll ON fh.user_id = ll.user_id 
                                                      AND fh.log_time >= ll.login_time 
                                                      AND (fh.log_time <= ll.logout_time OR ll.logout_time IS NULL)
                                      WHERE 
                                          ll.id IN ($placeholders)
                                      GROUP BY 
                                          ll.id, l.source_file
                                      ORDER BY 
                                          l.source_file";

                                $batch_stmt = $conn->prepare($batch_sql);
                                $batch_stmt->bind_param($types, ...$log_ids);
                                $batch_stmt->execute();
                                $batch_result = $batch_stmt->get_result();

                                // Organize the batch counts by their log_id for easy lookup
                                while ($row = $batch_result->fetch_assoc()) {
                                    $batch_counts[$row['log_id']][] = $row;
                                }
                                $batch_stmt->close();
                            }

                            // =================================================================
                            // ===== END: MODIFIED LOGS QUERY ==================================
                            // =================================================================

                            if (!empty($login_logs)) {
                                foreach ($login_logs as $log_row) {
                                    $login_time_formatted = date('d-m-Y h:i:s A', strtotime($log_row['login_time']));
                                    $logout_time_formatted = $log_row['logout_time'] === null
                                        ? "<span style='color:green; font-weight:bold;'>Active Session</span>"
                                        : date('d-m-Y h:i:s A', strtotime($log_row['logout_time']));

                                    echo "<tr>";
                                    echo "<td>" . htmlspecialchars($log_row['username']) . "</td>";
                                    echo "<td>" . htmlspecialchars($login_time_formatted) . "</td>";
                                    echo "<td>" . $logout_time_formatted . "</td>";

                                    // --- New Display Logic for Call Counts ---
                                    echo "<td>";
                                    if ($log_row['call_count'] > 0) {
                                        echo "<strong>Total: " . htmlspecialchars($log_row['call_count']) . "</strong>";
                                        if (isset($batch_counts[$log_row['id']])) {
                                            echo "<ul style='margin: 5px 0 0 15px; padding: 0; font-size: 0.9em;'>";
                                            foreach ($batch_counts[$log_row['id']] as $batch_info) {
                                                echo "<li>" . htmlspecialchars($batch_info['source_file']) . ": <strong>" . $batch_info['batch_call_count'] . "</strong></li>";
                                            }
                                            echo "</ul>";
                                        }
                                    } else {
                                        echo "0";
                                    }
                                    echo "</td>";
                                    // --- End New Display Logic ---

                                    echo "<td>" . htmlspecialchars($log_row['ip_address']) . "</td>";
                                    echo "</tr>";
                                }
                            } else {
                                echo "<tr><td colspan='5' style='text-align:center;'>No login history found.</td></tr>";
                            }
                            ?>
                        </tbody>
                    </table>
                </div>
                <?php
                // Add the pagination links
                echo generatePagination($total_logs, $per_page, $current_page, "index.php?view_logs=true");
                ?>
            </div>

        <?php // MODIFIED: Report Generation View with Date Filters and Single Select
        elseif ($current_mode === 'reports'): ?>
            <div class="form-container">
                <h3>Generate Reports
                    <a href="index.php" class="button-link back" style="float:right;">Back to Dashboard</a>
                </h3>

                <?php
                // Build the user list once for both forms
                $user_options_html = "";
                $user_list_sql = "";
                $user_params = [];
                $user_types = '';

                if ($_SESSION['role'] === 'admin') {
                    $user_list_sql = "SELECT id, username, role FROM users ORDER BY role, username";
                } elseif ($_SESSION['role'] === 'manager') {
                    // CORRECTED QUERY: Get self (the manager) AND users whose manager_id is the current user's ID
                    $user_list_sql = "SELECT id, username, role FROM users WHERE id = ? OR manager_id = ? ORDER BY username ASC";
                    $user_params = [$_SESSION['user_id'], $_SESSION['user_id']];
                    $user_types = 'ii';
                } else { // Member
                    $user_list_sql = "SELECT id, username, role FROM users WHERE id = ?";
                    $user_params = [$_SESSION['user_id']];
                    $user_types = 'i';
                }

                $user_stmt = $conn->prepare($user_list_sql);
                if (!empty($user_params)) {
                    $user_stmt->bind_param($user_types, ...$user_params);
                }
                $user_stmt->execute();
                $user_result = $user_stmt->get_result();

                if ($_SESSION['role'] === 'manager' || $_SESSION['role'] === 'admin') {
                    $user_options_html .= "<option value='team'>-- All My Team --</option>";
                }

                while ($user_row = $user_result->fetch_assoc()) {
                    $selected = ($_SESSION['role'] === 'member') ? 'selected' : '';
                    $user_options_html .= "<option value='{$user_row['id']}' $selected>" . htmlspecialchars($user_row['username']) . " (" . htmlspecialchars($user_row['role']) . ")</option>";
                }
                $user_stmt->close();
                ?>

                <!-- Printable Report Form -->
                <h4>Printable Performance Report</h4>
                <form method="GET" action="report.php" target="_blank" class="filter-form">
                    <div>
                        <label for="print_report_user">Select User:</label>
                        <select name="user" id="print_report_user" required>
                            <?php echo $user_options_html; ?>
                        </select>
                    </div>
                    <div id="print_batch_selection_div" style="display: none;">
                        <label for="print_report_batch_file">Select Batch:</label>
                        <select name="batch_file" id="print_report_batch_file">
                            <!-- Options will be populated by JavaScript -->
                        </select>
                    </div>
                    <div>
                        <label for="print_start_date">From:</label>
                        <input type="date" name="start_date" id="print_start_date" required>
                    </div>
                    <div>
                        <label for="print_end_date">To:</label>
                        <input type="date" name="end_date" id="print_end_date" required>
                    </div>
                    <button type="submit">Generate Printable Report</button>
                </form>

                <!-- Excel Export Form (Admin Only) -->
                <?php if ($_SESSION['role'] === 'admin'): ?>
                    <hr style="margin: 30px 0;">
                    <h4>Excel Data Export</h4>
                    <form method="POST" action="index.php" class="filter-form">
                        <div>
                            <label for="excel_report_user">Select User:</label>
                            <select name="report_users[]" id="excel_report_user" required>
                                <?php echo $user_options_html; ?>
                            </select>
                        </div>
                        <div id="excel_batch_selection_div" style="display: none;">
                            <label for="excel_report_batch_file">Select Batch:</label>
                            <select name="batch_file" id="excel_report_batch_file">
                                <!-- Options will be populated by JavaScript -->
                            </select>
                        </div>

                        <div>
                            <label for="excel_start_date">From:</label>
                            <input type="date" name="start_date" id="excel_start_date" required>
                        </div>
                        <div>
                            <label for="excel_end_date">To:</label>
                            <input type="date" name="end_date" id="excel_end_date" required>
                        </div>
                        <button type="submit" name="generate_report">Generate Excel Export</button>
                    </form>
                <?php endif; ?>
            </div>
        <?php // NEW: User Management View
        elseif ($current_mode === 'manage_users'): ?>

            <div class="form-container">
                <h3><?php echo $edit_user_data ? 'Edit User' : 'Add New User'; ?></h3>
                <form method="POST" action="index.php?manage_users=true">
                    <?php if ($edit_user_data): ?>
                        <input type="hidden" name="user_id" value="<?php echo $edit_user_data['id']; ?>">
                    <?php endif; ?>
                    <div class="form-grid">
                        <div>
                            <label for="username">Name (Username):</label><br>
                            <input type="text" id="username" name="username" value="<?php echo htmlspecialchars($edit_user_data['username'] ?? ''); ?>" required style="width:100%;">
                        </div>
                        <div>
                            <label for="email">Email:</label><br>
                            <input type="email" id="email" name="email" value="<?php echo htmlspecialchars($edit_user_data['email'] ?? ''); ?>" required style="width:100%;">
                        </div>

                        <?php
                        // SECURITY CHECK: Show Role/Manager fields ONLY IF:
                        // 1. We are adding a NEW user (edit_user_data is null)
                        // OR
                        // 2. We are editing a user that is NOT the currently logged-in admin
                        if (empty($edit_user_data) || $edit_user_data['id'] != $_SESSION['user_id']) :
                        ?>
                            <div>
                                <label for="role">Role:</label><br>
                                <select name="role" id="role_select" required style="width:100%;">
                                    <option value="member" <?php echo (($edit_user_data['role'] ?? '') === 'member') ? 'selected' : ''; ?>>Member</option>
                                    <option value="manager" <?php echo (($edit_user_data['role'] ?? '') === 'manager') ? 'selected' : ''; ?>>Manager</option>
                                </select>
                            </div>
                            <div id="manager_assignment_div" style="display: none;">
                                <label for="manager_id">Assign to Manager:</label><br>
                                <select name="manager_id" id="manager_id" style="width:100%;">
                                    <option value="">-- Select a Manager --</option>
                                    <?php
                                    $managers_result = $conn->query("SELECT id, username FROM users WHERE role = 'manager' ORDER BY username");
                                    while ($manager = $managers_result->fetch_assoc()) {
                                        $selected = (isset($edit_user_data['manager_id']) && $edit_user_data['manager_id'] == $manager['id']) ? 'selected' : '';
                                        echo "<option value='{$manager['id']}' $selected>" . htmlspecialchars($manager['username']) . "</option>";
                                    }
                                    ?>
                                </select>
                            </div>
                        <?php else: ?>
                            <!-- If editing self, we must still pass the role to the backend to avoid errors -->
                            <input type="hidden" name="role" value="<?php echo $edit_user_data['role']; ?>">
                        <?php endif; ?>

                        <div>
                            <label for="password">Password <?php if ($edit_user_data) echo "(leave blank to keep current)"; ?>:</label><br>
                            <div class="password-wrapper">
                                <input type="password" id="password" name="password" style="width:100%;" <?php echo $edit_user_data ? '' : 'required'; ?>>
                                <i class="fa-solid fa-eye password-toggle" onclick="togglePasswordVisibility('password', this)"></i>
                            </div>
                        </div>
                        <div>
                            <label for="confirm_password">Confirm Password:</label><br>
                            <div class="password-wrapper">
                                <input type="password" id="confirm_password" name="confirm_password" style="width:100%;" <?php echo $edit_user_data ? '' : 'required'; ?>>
                                <i class="fa-solid fa-eye password-toggle" onclick="togglePasswordVisibility('confirm_password', this)"></i>
                            </div>
                        </div>
                    </div>
                    <br>
                    <button type="submit" name="save_user"><?php echo $edit_user_data ? 'Update User' : 'Add User'; ?></button>
                    <?php if ($edit_user_data): ?>
                        <a href="?manage_users=true" class="button-link back">Cancel Edit</a>
                    <?php endif; ?>
                </form>
            </div>
            <!-- ========================================================================= -->
            <!-- END: RESTORED ADD/EDIT USER FORM                                          -->
            <!-- ========================================================================= -->


            <!-- User List Table -->
            <h3 style="margin-top: 40px;">Existing Users</h3>
            <div class="table-responsive-wrapper">
                <table>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Manager</th>
                        <th>Actions</th>
                    </tr>
                    <?php
                    $users_sql = "SELECT u.*, m.username as manager_name FROM users u LEFT JOIN users m ON u.manager_id = m.id ORDER BY u.role, u.username";
                    $users_result = $conn->query($users_sql);
                    while ($user = $users_result->fetch_assoc()):
                    ?>
                        <tr>
                            <td><?php echo $user['id']; ?></td>
                            <td><?php echo htmlspecialchars($user['username']); ?></td>
                            <td><?php echo htmlspecialchars($user['email']); ?></td>
                            <td><?php echo ucfirst($user['role']); ?></td>
                            <td><?php echo htmlspecialchars($user['manager_name'] ?? 'N/A'); ?></td>
                            <td style="white-space:nowrap;">
                                <a href="?manage_users=true&edit_user_id=<?php echo $user['id']; ?>" class="button-link edit">Edit</a>
                                <?php if ($user['id'] != $_SESSION['user_id']): // Can't delete self 
                                ?>
                                    <a href="?manage_users=true&delete_user_id=<?php echo $user['id']; ?>" class="button-link delete" onclick="return confirm('Are you sure you want to delete this user? This cannot be undone.')">Delete</a>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endwhile; ?>
                </table>
            </div>

        <?php // NEW: Manage Options View
        elseif ($current_mode === 'manage_options'): ?>
            <h3>Manage Dropdown Options
                <a href="index.php" class="button-link back" style="float:right;">Back to Dashboard</a>
            </h3>

            <div class="options-grid">
                <!-- Statuses Card -->
                <div class="options-card">
                    <h4>Statuses</h4>
                    <form method="POST" action="index.php?manage_options=true">
                        <input type="text" name="name" placeholder="New Status Name" required>
                        <input type="color" name="color" value="#28a745" required>
                        <button type="submit" name="add_status">Add</button>
                    </form>
                    <ul class="options-list">
                        <?php
                        $result = $conn->query("SELECT id, name, color FROM statuses ORDER BY name");
                        while ($row = $result->fetch_assoc()): ?>
                            <li>
                                <span><i class="fa-solid fa-square" style="color: <?php echo $row['color']; ?>;"></i> <?php echo htmlspecialchars($row['name']); ?></span>
                                <a href="?manage_options=true&delete_status_id=<?php echo $row['id']; ?>" class="delete-option" onclick="return confirm('Are you sure?')">Delete</a>
                            </li>
                        <?php endwhile; ?>
                    </ul>
                </div>

                <!-- Requirements Card -->
                <div class="options-card">
                    <h4>Requirements</h4>
                    <form method="POST" action="index.php?manage_options=true">
                        <input type="text" name="name" placeholder="New Requirement Name" required>
                        <button type="submit" name="add_requirement">Add</button>
                    </form>
                    <ul class="options-list">
                        <?php
                        $result = $conn->query("SELECT id, name FROM requirements ORDER BY name");
                        while ($row = $result->fetch_assoc()): ?>
                            <li>
                                <span><?php echo htmlspecialchars($row['name']); ?></span>
                                <a href="?manage_options=true&delete_requirement_id=<?php echo $row['id']; ?>" class="delete-option" onclick="return confirm('Are you sure?')">Delete</a>
                            </li>
                        <?php endwhile; ?>
                    </ul>
                </div>

                <!-- Communication Modes Card -->
                <div class="options-card">
                    <h4>Communication Modes</h4>
                    <form method="POST" action="index.php?manage_options=true">
                        <input type="text" name="name" placeholder="New Mode Name" required>
                        <button type="submit" name="add_comm_mode">Add</button>
                    </form>
                    <ul class="options-list">
                        <?php
                        $result = $conn->query("SELECT id, name FROM communication_modes ORDER BY name");
                        while ($row = $result->fetch_assoc()): ?>
                            <li>
                                <span><?php echo htmlspecialchars($row['name']); ?></span>
                                <a href="?manage_options=true&delete_comm_mode_id=<?php echo $row['id']; ?>" class="delete-option" onclick="return confirm('Are you sure?')">Delete</a>
                            </li>
                        <?php endwhile; ?>
                    </ul>
                </div>
            </div>


        <?php else: ?>
            <?php
            $role = $_SESSION['role'];
            $user_id = $_SESSION['user_id'];
            $batch_to_view = $_GET['view_batch'] ?? null;
            ?>
            <div class="actions-bar">
                <h3>Actions</h3>

                <!-- MODIFIED: This is now a simple button to open the modal -->
                <button type="button" id="openImportModalBtn">Import Leads from File</button>

                <a href="?reports=true" class="button-link reports">Generate Report</a>
                <a href="reminders.php" class="button-link" style="background-color:#ffc107; color: #212529;">
                    <i class="fa-solid fa-bell"></i> Reminders
                    <?php
                    $total_reminders = $today_reminders_count + $missed_reminders_count;
                    if ($total_reminders > 0) {
                        echo "<span style='background-color: #dc3545; color: white; border-radius: 50%; padding: 2px 6px; font-size: 0.8em; margin-left: 5px;'>$total_reminders</span>";
                    }
                    ?>
                </a>
                <?php if ($role === 'admin'): ?>
                    <a href="?manage_users=true" class="button-link" style="background-color:#5a0f66;">Manage Users</a>
                    <a href="?manage_options=true" class="button-link" style="background-color:#17a2b8;">Manage Options</a>
                <?php endif; ?>
                <?php if ($role === 'admin' || $role === 'manager'): ?>
                    <a href="?view_logs=true" class="button-link logs">View Login History</a>
                <?php endif; ?>
            </div>


            <?php // --- IF a specific batch is selected, show the DETAILED LEAD LIST ---
            if ($batch_to_view): ?>
                <h3>Leads in Batch: "<?php echo htmlspecialchars($batch_to_view); ?>"
                    <div style="float:right;">
                        <button type="button" id="openAddLeadModalBtn" class="button-link" style="background-color:#17a2b8; margin-right: 10px;">
                            <i class="fa-solid fa-plus"></i> Add New Lead
                        </button>
                        <a href="index.php" class="button-link back">Back to Batch List</a>
                    </div>
                </h3>

                <form method="GET" action="index.php" class="filter-form">
                    <input type="hidden" name="view_batch" value="<?php echo htmlspecialchars($batch_to_view); ?>">

                    <div>
                        <label for="search_term">Search:</label>
                        <input type="text" name="search_term" id="search_term" placeholder="Name, Phone, Status..." value="<?php echo htmlspecialchars($_GET['search_term'] ?? ''); ?>">
                    </div>

                    <div>
                        <label for="followup_filter_date">Follow-up Date:</label>
                        <input type="date" name="followup_filter_date" id="followup_filter_date" value="<?php echo htmlspecialchars($_GET['followup_filter_date'] ?? ''); ?>">
                    </div>

                    <div>
                        <label for="status">Status:</label>
                        <select name="status" id="status">
                            <option value="">-- All --</option>
                            <?php
                            $selected_status = $_GET['status'] ?? '';
                            foreach (array_keys($status_options) as $stat) {
                                $isSelected = ($selected_status == $stat) ? 'selected' : '';
                                echo "<option value=\"$stat\" $isSelected>$stat</option>";
                            }
                            ?>
                        </select>
                    </div>

                    <button type="submit">Apply Filters</button>
                    <a href="?view_batch=<?php echo urlencode($batch_to_view); ?>" class="button-link back" style="margin-right:0;">Clear</a>
                </form>

                <div class="table-responsive-wrapper">
                    <table>
                        <!-- MODIFIED: Add new table header -->
                        <tr>
                            <th>Name</th>
                            <th style="width: 15%;">Status</th>
                            <th style="width: 15%;">Requirement</th>
                            <th style="width: 15%;">Method</th>
                            <th>Phone</th>
                            <th>Follow-up</th>
                            <th>Next Follow-up</th>
                            <?php if ($role === 'admin' || $role === 'manager'): ?><th>Assigned To</th><?php endif; ?>
                            <th>Actions</th>
                        </tr>
                        <?php
                        // =================================================================
                        // ===== MODIFIED DATA FETCHING LOGIC WITH FILTERS =====
                        // =================================================================
                        $per_page = 50;
                        $current_page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
                        $offset = ($current_page - 1) * $per_page;

                        $base_sql = "FROM leads l JOIN users u ON l.user_id = u.id WHERE 1=1";
                        $params = [];
                        $types = '';

                        // Apply filters to both queries
                        if ($role === 'manager') {
                            $base_sql .= " AND (l.user_id = ? OR u.manager_id = ?)";
                            array_push($params, $user_id, $user_id);
                            $types .= "ii";
                        } elseif ($role === 'member') {
                            $base_sql .= " AND l.user_id = ?";
                            array_push($params, $user_id);
                            $types .= "i";
                        }

                        // 2. Batch file filtering (applied to SQL)
                        $base_sql .= " AND l.source_file = ?";
                        array_push($params, $batch_to_view);
                        $types .= "s";

                        // The search logic needs to run on the whole dataset, so we apply it in PHP later.
                        // But we can pre-filter by status and date to make the query faster.
                        if (isset($_GET['status']) && !empty($_GET['status'])) {
                            $base_sql .= " AND l.status = ?";
                            array_push($params, encryptData($_GET['status']));
                            $types .= "s";
                        }
                        if (isset($_GET['followup_filter_date']) && !empty($_GET['followup_filter_date'])) {
                            $filter_date = $_GET['followup_filter_date'];
                            $base_sql .= " AND (l.followup_date = ? OR l.next_followup_date = ?)";
                            array_push($params, $filter_date, $filter_date);
                            $types .= "ss";
                        }

                        $count_sql = "SELECT COUNT(l.id) as total " . $base_sql;
                        $count_stmt = $conn->prepare($count_sql);
                        if (!empty($params)) {
                            $count_stmt->bind_param($types, ...$params);
                        }
                        $count_stmt->execute();
                        $total_leads = $count_stmt->get_result()->fetch_assoc()['total'];
                        $count_stmt->close();

                        // Fetch the data for the current page
                        $sql_paginated = "SELECT l.*, u.username " . $base_sql . " ORDER BY l.id DESC LIMIT ? OFFSET ?";
                        $types .= "ii";
                        array_push($params, $per_page, $offset);

                        $stmt = $conn->prepare($sql_paginated);
                        $stmt->bind_param($types, ...$params);
                        $stmt->execute();
                        $leads_result = $stmt->get_result();

                        $leads_data = [];
                        while ($row = $leads_result->fetch_assoc()) {
                            $leads_data[] = $row;
                        }
                        $stmt->close();

                        // 5. Search term filtering (applied in PHP because fields are encrypted)
                        if (isset($_GET['search_term']) && !empty($_GET['search_term'])) {
                            $search_term = strtolower(trim($_GET['search_term']));
                            $filtered_leads = [];
                            foreach ($leads_data as $lead) {
                                $name = strtolower(decryptData($lead['name']));
                                $phone = decryptData($lead['phone']);
                                // NEW: Decrypt status and requirement for searching
                                $status = strtolower(decryptData($lead['status']));
                                $requirement = strtolower(decryptData($lead['requirement']));

                                if (
                                    strpos($name, $search_term) !== false ||
                                    strpos($phone, $search_term) !== false ||
                                    strpos($status, $search_term) !== false ||
                                    strpos($requirement, $search_term) !== false
                                ) {
                                    $filtered_leads[] = $lead;
                                }
                            }
                            $leads_data = $filtered_leads; // Overwrite the array with the filtered results
                        }

                        // Now, fetch followup history for the final set of leads
                        $lead_ids = array_column($leads_data, 'id');
                        $followup_history = [];
                        if (!empty($lead_ids)) {
                            $ids_string = implode(',', $lead_ids);
                            $history_sql = "SELECT fh.lead_id, fh.followup_date, u.username FROM followup_history fh JOIN users u ON fh.user_id = u.id WHERE fh.lead_id IN ($ids_string) ORDER BY fh.lead_id, fh.log_time DESC";
                            $history_result = $conn->query($history_sql);
                            while ($h_row = $history_result->fetch_assoc()) {
                                if (!isset($followup_history[$h_row['lead_id']]) || count($followup_history[$h_row['lead_id']]) < 5) {
                                    $followup_history[$h_row['lead_id']][] = $h_row;
                                }
                            }
                        }

                        $colspan = ($role === 'admin' || $role === 'manager') ? 9 : 8;
                        if (count($leads_data) > 0) {
                            foreach ($leads_data as $row) {
                                $current_status = decryptData($row['status']);
                                $current_requirement = decryptData($row['requirement']);
                                $is_other_requirement = !in_array($current_requirement, $requirement_options) && !empty($current_requirement);
                                $current_comm_mode = decryptData($row['communication_mode']);
                                $is_other_comm_mode = !in_array($current_comm_mode, $communication_mode_options) && !empty($current_comm_mode);
                                $history_for_this_lead = $followup_history[$row['id']] ?? [];


                                echo "<tr>";
                                echo "<td>" . htmlspecialchars(decryptData($row['name'])) . "</td>";

                                // CORRECTED: Status Dropdown
                                echo "<td><select class='lead-update-dropdown status-dropdown' data-lead-id='{$row['id']}' data-field='status' style='background-color: " . ($status_options[$current_status] ?? '#6c757d') . ";'>";
                                foreach ($status_options as $option => $color) {
                                    echo "<option value=\"$option\" " . ($current_status == $option ? 'selected' : '') . ">$option</option>";
                                }
                                echo "</select></td>";

                                // CORRECTED: Requirement Dropdown
                                echo "<td>";
                                echo "<div class='searchable-dropdown-wrapper'>"; // A simple wrapper
                                echo "<div class='searchable-dropdown'>";
                                // The hidden select now has the data attributes for our AJAX to find
                                echo "<select class='lead-update-dropdown requirement-dropdown' data-lead-id='{$row['id']}' data-field='requirement' style='display:none;'>";
                                foreach ($requirement_options as $option) {
                                    if ($option === 'Other' && $is_other_requirement) {
                                        echo "<option value=\"Other\" selected>Other</option>";
                                    } else {
                                        echo "<option value=\"$option\" " . ($current_requirement == $option ? 'selected' : '') . ">$option</option>";
                                    }
                                }
                                echo "</select>";
                                // The visible input for searching
                                echo "<input type='text' class='searchable-dropdown-input' placeholder='Search or select...' value='" . htmlspecialchars($current_requirement) . "'>";
                                // The options list
                                echo "<div class='searchable-dropdown-options'>";
                                foreach ($requirement_options as $option) {
                                    echo "<div data-value=\"$option\">$option</div>";
                                }
                                echo "</div>"; // end options
                                echo "</div>"; // end searchable-dropdown

                                // Add back the "Other" text input, controlled by JS
                                echo "<input type='text' class='lead-update-input other-requirement-input' data-lead-id='{$row['id']}' data-field='requirement' placeholder='Specify other requirement' value='" . ($is_other_requirement ? htmlspecialchars($current_requirement) : '') . "' style='display: " . ($is_other_requirement ? 'block' : 'none') . "; margin-top: 5px; width: 100%;'>";
                                echo "</div>"; // end wrapper
                                echo "</td>";

                                // CORRECTED: Communication Mode dropdown (was already correct, but ensuring it's not abbreviated)
                                echo "<td>";
                                echo "<select class='lead-update-dropdown comm-mode-dropdown' data-lead-id='{$row['id']}' data-field='communication_mode'>";
                                echo "<option value=''>-- Select --</option>";
                                foreach ($communication_mode_options as $option) {
                                    if ($option === 'Other' && $is_other_comm_mode) {
                                        echo "<option value=\"Other\" selected>Other</option>";
                                    } else {
                                        $selected = ($current_comm_mode == $option) ? 'selected' : '';
                                        echo "<option value=\"$option\" $selected>$option</option>";
                                    }
                                }
                                echo "</select>";
                                echo "<input type='text' class='lead-update-input other-comm-mode-input' data-lead-id='{$row['id']}' data-field='communication_mode' placeholder='Specify other mode' value='" . ($is_other_comm_mode ? htmlspecialchars($current_comm_mode) : '') . "' style='display: " . ($is_other_comm_mode ? 'block' : 'none') . "; margin-top: 5px; width: 100%;'>";
                                echo "</td>";

                                // Unchanged fields
                                // Unchanged fields
                                echo "<td>" . htmlspecialchars(formatPhoneNumber(decryptData($row['phone']))) . "</td>";
                                echo "<td><div style='display:flex; align-items:center;'>";
                                echo "<input type='date' class='lead-update-input followup-date-picker' data-lead-id='{$row['id']}' data-field='followup_date' value='{$row['followup_date']}'>";
                                if (!empty($history_for_this_lead)) {
                                    echo "<i class='fa-solid fa-clock-rotate-left history-icon' data-history='" . htmlspecialchars(json_encode($history_for_this_lead), ENT_QUOTES, 'UTF-8') . "'></i>";
                                }
                                echo "</div></td>";

                                // Next Follow-up Date with dynamic JS class
                                echo "<td><input type='date' class='lead-update-input next-followup-date-picker' data-lead-id='{$row['id']}' data-field='next_followup_date' value='{$row['next_followup_date']}'></td>";
                                if ($role === 'admin' || $role === 'manager') {
                                    echo "<td>" . htmlspecialchars($row['username']) . "</td>";
                                }

                                // CORRECTED: Action Buttons
                                echo "<td style='white-space: nowrap;'>";
                                echo "<a href='?view_id={$row['id']}' class='button-link' style='background-color:#17a2b8;'>View</a>";
                                if ($role === 'admin' || $role === 'manager') {
                                    echo "<a href='?delete_id={$row['id']}&view_batch=" . urlencode($batch_to_view) . "' class='button-link delete' onclick=\"return confirm('Are you sure you want to permanently delete this lead? This cannot be undone.');\">Delete</a>";
                                }
                                echo "</td>";
                                echo "</tr>";
                            }
                        } else {
                            echo "<tr><td colspan='$colspan' style='text-align:center;'>No leads found in this batch matching your criteria.</td></tr>";
                        }

                        ?>
                    </table>
                </div> <!-- End of table-responsive-wrapper -->
                <?php
                // Add the pagination links below the table
                $base_pagination_url = "index.php?view_batch=" . urlencode($batch_to_view);
                if (isset($_GET['search_term'])) $base_pagination_url .= "&search_term=" . urlencode($_GET['search_term']);
                if (isset($_GET['followup_filter_date'])) $base_pagination_url .= "&followup_filter_date=" . $_GET['followup_filter_date'];
                if (isset($_GET['status'])) $base_pagination_url .= "&status=" . $_GET['status'];
                echo generatePagination($total_leads, $per_page, $current_page, $base_pagination_url);
                ?>
            <?php // --- OTHERWISE, show the BATCH LIST TABLE by default ---
            else: ?>
                <div class="filter-form">
                    <label for="batch_search">Search Batches:</label>
                    <input type="text" id="batch_search" placeholder="Enter batch name..." style="width: 300px;">
                </div>

                <h3>My Imported Batches</h3>
                <div class="table-responsive-wrapper">
                    <table id="my_batch_table">
                        <thead>
                            <tr>
                                <th>Batch Name (Filename)</th>
                                <th>Lead Count</th>
                                <?php if ($role === 'member'): ?>
                                    <th>Assigned By</th>
                                <?php endif; ?>
                                <th style="width: 25%;">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php
                            $my_batches_sql = "";

                            if ($role === 'member') {
                                // Member's query now joins to get the importer's name
                                $my_batches_sql = "SELECT l.source_file, COUNT(l.id) as lead_count, imp.username as importer_name
                                             FROM leads l
                                             LEFT JOIN users imp ON l.imported_by = imp.id
                                             WHERE l.user_id = ? AND l.source_file IS NOT NULL 
                                             GROUP BY l.source_file, imp.username 
                                             ORDER BY l.source_file DESC";
                            } else {
                                // Admin/Manager query remains the same
                                $my_batches_sql = "SELECT source_file, COUNT(id) as lead_count 
                                              FROM leads 
                                              WHERE user_id = ? AND source_file IS NOT NULL 
                                              GROUP BY source_file 
                                              ORDER BY source_file DESC";
                            }

                            $my_batches_stmt = $conn->prepare($my_batches_sql);
                            $my_batches_stmt->bind_param("i", $user_id);
                            $my_batches_stmt->execute();
                            $my_batches_result = $my_batches_stmt->get_result();

                            $colspan = ($role === 'member') ? 4 : 3;

                            if ($my_batches_result->num_rows > 0) {
                                while ($batch_row = $my_batches_result->fetch_assoc()) {
                                    echo "<tr>";
                                    echo "<td><strong>" . htmlspecialchars($batch_row['source_file']) . "</strong></td>";
                                    echo "<td>" . $batch_row['lead_count'] . "</td>";

                                    if ($role === 'member') {
                                        $importer_name = $batch_row['importer_name'] ?? 'Self';
                                        if ($batch_row['importer_name'] == $_SESSION['username']) {
                                            $importer_name = 'Self';
                                        }
                                        echo "<td>" . htmlspecialchars($importer_name) . "</td>";
                                    }

                                    echo "<td style='white-space: nowrap;'>";
                                    echo "<a href='?view_batch=" . urlencode($batch_row['source_file']) . "' class='button-link' style='background-color:#007bff;'>View Leads</a>";
                                    if ($role === 'admin' || $role === 'manager') {
                                        echo "<a href='?delete_batch=" . urlencode($batch_row['source_file']) . "' class='button-link delete' onclick=\"return confirm('Are you sure? This will delete the entire batch and its leads.');\">Delete Batch</a>";
                                    }
                                    echo "</td>";
                                    echo "</tr>";
                                }
                            } else {
                                echo "<tr><td colspan='$colspan' style='text-align:center;'>You have not imported any batches for yourself.</td></tr>";
                            }
                            $my_batches_stmt->close();
                            ?>
                        </tbody>
                    </table>
                </div> <!-- End of table-responsive-wrapper -->

                <?php if ($role === 'admin' || $role === 'manager'): ?>
                    <h3 style="margin-top: 40px;">Batches Assigned to Others</h3>
                    <div class="table-responsive-wrapper">
                        <table id="assigned_batch_table">
                            <thead>
                                <tr>
                                    <th>Batch Name (Filename)</th>
                                    <th>Assigned To</th>
                                    <th>Lead Count</th>
                                    <th style="width: 25%;">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php
                                // --- CORRECTED QUERY for leads imported BY the logged-in user but assigned to OTHERS ---
                                $assigned_sql_base = "SELECT l.source_file, u.username as assigned_to_user, COUNT(l.id) as lead_count 
                                             FROM leads l 
                                             JOIN users u ON l.user_id = u.id 
                                             WHERE l.imported_by = ? AND l.user_id != ?";
                                $assigned_params = [$user_id, $user_id];
                                $assigned_types = "ii";

                                if ($role === 'manager') {
                                    // Manager can only see batches assigned to their direct reports
                                    $assigned_sql_base .= " AND u.manager_id = ?";
                                    $assigned_params[] = $user_id;
                                    $assigned_types .= "i";
                                }

                                $assigned_sql = $assigned_sql_base . " AND l.source_file IS NOT NULL GROUP BY l.source_file, u.username ORDER BY l.source_file DESC";

                                $assigned_stmt = $conn->prepare($assigned_sql);
                                $assigned_stmt->bind_param($assigned_types, ...$assigned_params);
                                $assigned_stmt->execute();
                                $assigned_result = $assigned_stmt->get_result();

                                if ($assigned_result->num_rows > 0) {
                                    while ($batch_row = $assigned_result->fetch_assoc()) {
                                        echo "<tr>";
                                        echo "<td><strong>" . htmlspecialchars($batch_row['source_file']) . "</strong></td>";
                                        echo "<td>" . htmlspecialchars($batch_row['assigned_to_user']) . "</td>";
                                        echo "<td>" . $batch_row['lead_count'] . "</td>";
                                        echo "<td style='white-space: nowrap;'>";
                                        echo "<a href='?delete_batch=" . urlencode($batch_row['source_file']) . "' class='button-link delete' onclick=\"return confirm('Are you sure? This will delete the entire batch and its leads.');\">Delete Batch</a>";
                                        echo "</td>";
                                        echo "</tr>";
                                    }
                                } else {
                                    echo "<tr><td colspan='4' style='text-align:center;'>You have not assigned any batches to other users.</td></tr>";
                                }
                                $assigned_stmt->close();
                                ?>
                            </tbody>
                        </table>
                        <div class="table-responsive-wrapper">
                        <?php endif; ?>
                    <?php endif; ?>
                <?php endif; ?>
                        </div>
                        <footer class="main-footer">
                            Copyright © <?php echo date('Y'); ?> | Developed by <span class="company-name">THE UNIQUE CULTURE</span>
                        </footer>
                        <div id="importModal" class="modal-overlay">
                            <div class="modal-content">
                                <span class="modal-close" id="closeImportModalBtn">×</span>
                                <h3>Import Leads</h3>
                                <a href="?download_template=true" class="button-link" style="background-color:#17a2b8; float:right; margin-top:-50px;">
                                    <i class="fa-solid fa-download"></i> Download Template
                                </a>
                                <form method="POST" enctype="multipart/form-data" action="index.php">

                                    <?php if ($_SESSION['role'] === 'admin' || $_SESSION['role'] === 'manager'): ?>
                                        <p>Who are these leads for?</p>
                                        <input type="radio" name="import_type" id="import_self" value="self" checked>
                                        <label for="import_self">Import for Myself (<?php echo htmlspecialchars($_SESSION['username']); ?>)</label>
                                        <br>
                                        <input type="radio" name="import_type" id="import_other" value="other">
                                        <label for="import_other">Import for Another User</label>

                                        <div id="user_selection_div">
                                            <label for="import_for_user_id">Select User:</label>
                                            <select name="import_for_user_id" id="import_for_user_id">
                                                <?php
                                                $user_list_sql = "";
                                                if ($_SESSION['role'] === 'admin') {
                                                    // Admin can assign to anyone
                                                    $user_list_sql = "SELECT id, username, role FROM users ORDER BY role, username";
                                                    $user_stmt = $conn->query($user_list_sql);
                                                } else { // Manager
                                                    // Manager can assign to self or their members
                                                    $user_list_sql = "SELECT id, username, role FROM users WHERE id = ? OR manager_id = ? ORDER BY role, username";
                                                    $user_stmt = $conn->prepare($user_list_sql);
                                                    $user_stmt->bind_param("ii", $_SESSION['user_id'], $_SESSION['user_id']);
                                                    $user_stmt->execute();
                                                    $user_stmt = $user_stmt->get_result();
                                                }

                                                if ($user_stmt) {
                                                    while ($user = $user_stmt->fetch_assoc()) {
                                                        echo "<option value='{$user['id']}'>" . htmlspecialchars($user['username']) . " (" . $user['role'] . ")</option>";
                                                    }
                                                }
                                                ?>
                                            </select>
                                        </div>
                                        <hr style="margin: 20px 0;">
                                    <?php endif; ?>

                                    <label for="file">Select File (.csv, .xlsx, .xls):</label><br><br>
                                    <input type="file" name="file" accept=".csv, .xls, .xlsx" required>
                                    <br><br>
                                    <button type="submit" name="import">Start Import</button>
                                </form>
                            </div>
                        </div>
                        <?php
                        // =================================================================
                        // ===== START: SKIPPED LEADS MODAL DISPLAY LOGIC ==================
                        // =================================================================
                        if (isset($_SESSION['skipped_leads']) && !empty($_SESSION['skipped_leads'])):
                            $skipped_leads_data = $_SESSION['skipped_leads'];
                            unset($_SESSION['skipped_leads']); // Clear session variable after reading
                        ?>
                            <div id="skippedLeadsModal" class="modal-overlay" style="display: flex;">
                                <div class="modal-content">
                                    <span class="modal-close" id="closeSkippedLeadsBtn">×</span>
                                    <h3>Skipped Leads</h3>
                                    <p>The following leads were not imported because they were duplicates or had missing phone numbers.</p>
                                    <div class="skipped-leads-container">
                                        <div class="table-responsive-wrapper">
                                            <table class="skipped-leads-table">
                                                <thead>
                                                    <tr>
                                                        <th>Name</th>
                                                        <th>Phone</th>
                                                        <th>Reason for Skipping</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <?php foreach ($skipped_leads_data as $skipped): ?>
                                                        <tr>
                                                            <td><?php echo htmlspecialchars($skipped['name']); ?></td>
                                                            <td><?php echo htmlspecialchars($skipped['phone']); ?></td>
                                                            <td><?php echo htmlspecialchars($skipped['reason']); ?></td>
                                                        </tr>
                                                    <?php endforeach; ?>
                                                </tbody>
                                            </table>
                                        </div> <!-- End of table-responsive-wrapper -->
                                    </div>
                                    <br>
                                    <button type="button" id="okSkippedLeadsBtn" class="button-link back" style="float: right;">OK</button>
                                </div>
                            </div>
                        <?php
                        // =================================================================
                        // ===== END: SKIPPED LEADS MODAL DISPLAY LOGIC ====================
                        // =================================================================
                        endif;
                        ?>


                        <?php if (isset($_GET['view_batch'])): // Only render this modal if we are in a batch view 
                        ?>
                            <div id="addLeadModal" class="modal-overlay">
                                <div class="modal-content" style="width: 800px; max-width: 95%;">
                                    <span class="modal-close" id="closeAddLeadBtn">×</span>
                                    <h3>Add New Lead to "<?php echo htmlspecialchars($_GET['view_batch']); ?>"</h3>

                                    <form method="POST" action="index.php">
                                        <input type="hidden" name="source_file" value="<?php echo htmlspecialchars($_GET['view_batch']); ?>">

                                        <div class="form-grid">
                                            <div>
                                                <label for="add_name">Name:</label><br>
                                                <input type="text" id="add_name" name="name" required style="width:100%;">
                                            </div>
                                            <div>
                                                <label for="add_phone">Phone:</label><br>
                                                <input type="text" id="add_phone" name="phone" required style="width:100%;">
                                            </div>
                                            <div>
                                                <label for="add_status">Status:</label><br>
                                                <select name="status" id="add_status" required style="width:100%;">
                                                    <?php
                                                    foreach ($status_options as $option => $color) {
                                                        $selected = ($option == 'Follow-up') ? 'selected' : ''; // Default to Follow-up
                                                        echo "<option value=\"$option\" $selected>$option</option>";
                                                    }
                                                    ?>
                                                </select>
                                            </div>
                                            <div>
                                                <label for="add_followup_date">Follow-up Date:</label><br>
                                                <input type="date" id="add_followup_date" name="followup_date" style="width:100%;">
                                            </div>
                                            <div>
                                                <label for="add_next_followup_date">Next Follow-up Date:</label><br>
                                                <input type="date" id="add_next_followup_date" name="next_followup_date" style="width:100%;">
                                            </div>
                                            <div>
                                                <label for="add_source">Source:</label><br>
                                                <input type="text" id="add_source" name="source" style="width:100%;">
                                            </div>
                                            <div>
                                                <label for="add_requirement_select">Requirement:</label><br>
                                                <select name="requirement_select" id="add_requirement_select" style="width:100%;">
                                                    <?php
                                                    foreach ($requirement_options as $option) {
                                                        echo "<option value=\"$option\">$option</option>";
                                                    }
                                                    ?>
                                                </select>
                                                <input type="text" name="other_requirement_text" id="add_other_requirement_text" placeholder="Specify other requirement" style="width:100%; margin-top: 5px; display: none;">
                                            </div>
                                            <div>
                                                <label for="add_comm_mode_select">Mode of Communication:</label><br>
                                                <select name="communication_mode_select" id="add_comm_mode_select" style="width:100%;">
                                                    <?php
                                                    foreach ($communication_mode_options as $option) {
                                                        echo "<option value=\"$option\">$option</option>";
                                                    }
                                                    ?>
                                                </select>
                                                <input type="text" name="other_communication_mode_text" id="add_other_comm_mode_text" placeholder="Specify other mode" style="width:100%; margin-top: 5px; display: none;">
                                            </div>
                                        </div>
                                        <div style="margin-top: 15px;"><label for="add_service">Service:</label><br><textarea name="service" id="add_service" rows="2"></textarea></div>
                                        <div style="margin-top: 15px;"><label for="add_feedback">Feedback:</label><br><textarea name="feedback" id="add_feedback" rows="2"></textarea></div>
                                        <div style="margin-top: 15px;"><label for="add_comments">Internal Comments:</label><br><textarea name="comments" id="add_comments" rows="2"></textarea></div>
                                        <br>
                                        <button type="submit" name="add_lead_to_batch">Save New Lead</button>
                                    </form>
                                </div>
                            </div>
                        <?php endif; ?>

                        <div id="historyPopover" class="popover"></div>

                        <!-- The Javascript block remains largely unchanged, as it's designed to work with the elements present in the detailed lead list. I've added the edit form logic here for completeness. -->
                        <script>
                            document.addEventListener('DOMContentLoaded', function() {
                                const statusColors = <?php echo json_encode($status_options); ?>;
                                document.querySelectorAll('.lead-update-dropdown, .lead-update-input').forEach(field => {
                                    field.addEventListener('change', function() {
                                        const leadId = this.dataset.leadId;
                                        const fieldName = this.dataset.field;
                                        let newValue = this.value;
                                        if (this.classList.contains('other-requirement-input') || this.classList.contains('other-comm-mode-input')) {
                                            newValue = this.value;
                                        }
                                        if (fieldName === 'status') {
                                            this.style.backgroundColor = statusColors[newValue] || '#6c757d';
                                        }
                                        const formData = new FormData();
                                        formData.append('ajax_update', true);
                                        formData.append('lead_id', leadId);
                                        formData.append('field', fieldName);
                                        formData.append('value', newValue);

                                        // FIX: This is the crucial line that was missing
                                        const inputElement = this;

                                        fetch('index.php', {
                                                method: 'POST',
                                                body: formData
                                            })
                                            .then(response => response.json())
                                            .then(data => {
                                                if (data.status === 'error') {
                                                    alert('Update failed: ' + data.message);
                                                } else {
                                                    console.log('Update successful: ' + data.message);
                                                    if (fieldName === 'followup_date' && data.new_history_entry) {
                                                        const iconContainer = inputElement.parentElement;
                                                        let historyIcon = iconContainer.querySelector('.history-icon');
                                                        let currentHistory = [];
                                                        if (historyIcon) {
                                                            currentHistory = JSON.parse(historyIcon.getAttribute('data-history'));
                                                        } else {
                                                            historyIcon = document.createElement('i');
                                                            historyIcon.className = 'fa-solid fa-clock-rotate-left history-icon';
                                                            iconContainer.appendChild(historyIcon);
                                                        }
                                                        currentHistory.unshift(data.new_history_entry);
                                                        if (currentHistory.length > 5) {
                                                            currentHistory = currentHistory.slice(0, 5);
                                                        }
                                                        historyIcon.setAttribute('data-history', JSON.stringify(currentHistory));
                                                    }
                                                }
                                            })
                                            .catch(error => {
                                                console.error('Fetch Error:', error);
                                                alert('A network or server error occurred. Please check the console and try again.');
                                            });
                                    });
                                });
                                document.querySelectorAll('.requirement-dropdown').forEach(dropdown => {
                                    dropdown.addEventListener('change', function() {
                                        const otherInput = this.parentElement.querySelector('.other-requirement-input');
                                        if (otherInput) {
                                            if (this.value === 'Other') {
                                                otherInput.style.display = 'block';
                                                otherInput.focus();
                                            } else {
                                                otherInput.style.display = 'none';
                                                if (otherInput.value !== '') {
                                                    otherInput.value = '';
                                                }
                                            }
                                        }
                                    });
                                });
                                document.querySelectorAll('.comm-mode-dropdown').forEach(dropdown => {
                                    dropdown.addEventListener('change', function() {
                                        const otherInput = this.parentElement.querySelector('.other-comm-mode-input');
                                        if (otherInput) {
                                            if (this.value === 'Other') {
                                                otherInput.style.display = 'block';
                                                otherInput.focus();
                                            } else {
                                                otherInput.style.display = 'none';
                                                if (otherInput.value !== '') {
                                                    otherInput.value = '';
                                                }
                                            }
                                        }
                                    });
                                });

                                function setupSearchableDropdown(container) {
                                    const input = container.querySelector('.searchable-dropdown-input');
                                    const optionsContainer = container.querySelector('.searchable-dropdown-options');
                                    const allOptions = optionsContainer.querySelectorAll('div');
                                    const hiddenSelect = container.querySelector('select');

                                    // Find the associated "Other" input field, if it exists
                                    const wrapper = container.closest('.searchable-dropdown-wrapper');
                                    const otherInput = wrapper ? wrapper.querySelector('.other-requirement-input') : null;

                                    // Show options when user clicks/focuses on the input
                                    input.addEventListener('focus', () => {
                                        optionsContainer.style.display = 'block';
                                    });

                                    // Filter options as user types
                                    input.addEventListener('keyup', () => {
                                        const filter = input.value.toLowerCase();
                                        allOptions.forEach(optionDiv => {
                                            if (optionDiv.textContent.toLowerCase().indexOf(filter) > -1) {
                                                optionDiv.style.display = '';
                                            } else {
                                                optionDiv.style.display = 'none';
                                            }
                                        });
                                    });

                                    // Handle selection when user clicks an option
                                    allOptions.forEach(optionDiv => {
                                        optionDiv.addEventListener('click', () => {
                                            const selectedValue = optionDiv.getAttribute('data-value');
                                            input.value = selectedValue;
                                            optionsContainer.style.display = 'none';
                                            hiddenSelect.value = selectedValue;

                                            // Manually trigger the 'change' event to save the data via AJAX
                                            const changeEvent = new Event('change', {
                                                bubbles: true
                                            });
                                            hiddenSelect.dispatchEvent(changeEvent);
                                        });
                                    });
                                }

                                // Initialize all searchable dropdowns on the page
                                document.querySelectorAll('.searchable-dropdown').forEach(setupSearchableDropdown);

                                // Hide dropdowns if user clicks outside of them
                                document.addEventListener('click', function(e) {
                                    document.querySelectorAll('.searchable-dropdown').forEach(container => {
                                        if (!container.contains(e.target)) {
                                            container.querySelector('.searchable-dropdown-options').style.display = 'none';
                                        }
                                    });
                                });

                                // --- UNIVERSAL "OTHER" LOGIC FOR BOTH LIST VIEW & EDIT FORM ---
                                // This now handles ANY requirement dropdown on the page.
                                document.querySelectorAll('.requirement-dropdown').forEach(selectElement => {
                                    selectElement.addEventListener('change', function() {
                                        // Find the "other" input field relative to the select element's wrapper
                                        const wrapper = this.closest('.searchable-dropdown-wrapper, .form-container');
                                        if (wrapper) {
                                            const otherInput = wrapper.querySelector('.other-requirement-input, #other_requirement_edit');
                                            if (otherInput) {
                                                if (this.value === 'Other') {
                                                    otherInput.style.display = 'block';
                                                    otherInput.focus();
                                                } else {
                                                    otherInput.style.display = 'none';
                                                }
                                            }
                                        }
                                    });
                                });
                                const commModeEditSelect = document.getElementById('comm_mode_edit_select');
                                const otherCommModeEditInput = document.getElementById('other_comm_mode_edit');
                                if (commModeEditSelect && otherCommModeEditInput) {
                                    commModeEditSelect.addEventListener('change', function() {
                                        if (this.value === 'Other') {
                                            otherCommModeEditInput.style.display = 'block';
                                            otherCommModeEditInput.focus();
                                        } else {
                                            otherCommModeEditInput.style.display = 'none';
                                        }
                                    });
                                }

                                const roleSelect = document.getElementById('role_select');
                                const managerDiv = document.getElementById('manager_assignment_div');
                                const managerSelect = document.getElementById('manager_id');

                                if (roleSelect && managerDiv && managerSelect) {
                                    // Function to toggle manager field visibility and requirement
                                    const toggleManagerField = () => {
                                        if (roleSelect.value === 'member') {
                                            managerDiv.style.display = 'block';
                                            managerSelect.required = true; // Make it a required field
                                        } else {
                                            managerDiv.style.display = 'none';
                                            managerSelect.required = false; // Not required if hidden
                                            managerSelect.value = ''; // Clear selection when hiding
                                        }
                                    };

                                    // Add event listener for when the role is changed
                                    roleSelect.addEventListener('change', toggleManagerField);

                                    // Run on page load to set the initial state correctly (very important for editing users)
                                    toggleManagerField();
                                }
                                const skippedLeadsModal = document.getElementById('skippedLeadsModal');
                                if (skippedLeadsModal) {
                                    const closeBtn = document.getElementById('closeSkippedLeadsBtn');
                                    const okBtn = document.getElementById('okSkippedLeadsBtn');

                                    const closeModal = () => {
                                        skippedLeadsModal.style.display = 'none';
                                    };

                                    closeBtn.addEventListener('click', closeModal);
                                    okBtn.addEventListener('click', closeModal);

                                    window.addEventListener('click', (event) => {
                                        if (event.target === skippedLeadsModal) {
                                            closeModal();
                                        }
                                    });
                                }
                                const openModalBtn = document.getElementById('openImportModalBtn');
                                const closeModalBtn = document.getElementById('closeImportModalBtn');
                                const modal = document.getElementById('importModal');
                                const importSelfRadio = document.getElementById('import_self');
                                const importOtherRadio = document.getElementById('import_other');
                                const userSelectionDiv = document.getElementById('user_selection_div');
                                const userSelectDropdown = document.getElementById('import_for_user_id');

                                if (openModalBtn) {
                                    openModalBtn.addEventListener('click', () => {
                                        modal.style.display = 'flex';
                                    });
                                }

                                if (closeModalBtn) {
                                    closeModalBtn.addEventListener('click', () => {
                                        modal.style.display = 'none';
                                    });
                                }

                                // Close modal if user clicks outside the content area
                                window.addEventListener('click', (event) => {
                                    if (event.target === modal) {
                                        modal.style.display = 'none';
                                    }
                                });

                                // Logic to show/hide the user dropdown
                                if (importSelfRadio && importOtherRadio) {
                                    importSelfRadio.addEventListener('change', () => {
                                        if (importSelfRadio.checked) {
                                            userSelectionDiv.style.display = 'none';
                                            userSelectDropdown.removeAttribute('name'); // Important: remove name so it's not submitted
                                        }
                                    });

                                    importOtherRadio.addEventListener('change', () => {
                                        if (importOtherRadio.checked) {
                                            userSelectionDiv.style.display = 'block';
                                            userSelectDropdown.setAttribute('name', 'import_for_user_id'); // Add name back
                                        }
                                    });

                                    // Initial state check
                                    if (importSelfRadio.checked) {
                                        userSelectDropdown.removeAttribute('name');
                                    }
                                }

                                const addLeadModal = document.getElementById('addLeadModal');
                                if (addLeadModal) {
                                    const openBtn = document.getElementById('openAddLeadModalBtn');
                                    const closeBtn = document.getElementById('closeAddLeadBtn');

                                    openBtn.addEventListener('click', () => {
                                        addLeadModal.style.display = 'flex';
                                    });

                                    closeBtn.addEventListener('click', () => {
                                        addLeadModal.style.display = 'none';
                                    });

                                    window.addEventListener('click', (event) => {
                                        if (event.target === addLeadModal) {
                                            addLeadModal.style.display = 'none';
                                        }
                                    });

                                    // Logic for the "Other" fields in the Add Lead form
                                    const addReqSelect = document.getElementById('add_requirement_select');
                                    const addOtherReqInput = document.getElementById('add_other_requirement_text');
                                    addReqSelect.addEventListener('change', function() {
                                        addOtherReqInput.style.display = (this.value === 'Other') ? 'block' : 'none';
                                    });

                                    const addCommSelect = document.getElementById('add_comm_mode_select');
                                    const addOtherCommInput = document.getElementById('add_other_comm_mode_text');
                                    addCommSelect.addEventListener('change', function() {
                                        addOtherCommInput.style.display = (this.value === 'Other') ? 'block' : 'none';
                                    });
                                }
                                const popover = document.getElementById('historyPopover');

                                document.body.addEventListener('mouseover', function(event) {
                                    if (event.target.classList.contains('history-icon')) {
                                        const historyData = JSON.parse(event.target.getAttribute('data-history'));
                                        let content = '<h4>Follow-up History</h4>';

                                        if (historyData.length > 0) {
                                            content += '<ul>';
                                            historyData.forEach(entry => {
                                                content += `<li><strong>${entry.followup_date}</strong> by ${entry.username}</li>`;
                                            });
                                            content += '</ul>';
                                        } else {
                                            content += '<p>No history available.</p>';
                                        }

                                        popover.innerHTML = content;

                                        const rect = event.target.getBoundingClientRect();
                                        popover.style.left = rect.left + window.scrollX + 'px';
                                        popover.style.top = rect.bottom + window.scrollY + 5 + 'px'; // 5px below the icon
                                        popover.style.display = 'block';
                                    }
                                });



                                const batchSearchInput = document.getElementById('batch_search');
                                if (batchSearchInput) {
                                    batchSearchInput.addEventListener('keyup', function() {
                                        const searchTerm = this.value.toLowerCase();
                                        const tableBodies = document.querySelectorAll('#my_batch_table tbody, #assigned_batch_table tbody');

                                        tableBodies.forEach(tbody => {
                                            const rows = tbody.querySelectorAll('tr');
                                            rows.forEach(row => {
                                                // Check if the first cell (batch name) contains the search term
                                                const batchName = row.cells[0].textContent.toLowerCase();
                                                if (batchName.includes(searchTerm)) {
                                                    row.style.display = '';
                                                } else {
                                                    row.style.display = 'none';
                                                }
                                            });
                                        });
                                    });
                                }


                                document.querySelectorAll('.followup-date-picker').forEach(followupPicker => {
                                    followupPicker.addEventListener('change', function() {
                                        const row = this.closest('tr');
                                        const nextFollowupPicker = row.querySelector('.next-followup-date-picker');
                                        if (this.value) {
                                            // Set the minimum allowed date for the next followup
                                            nextFollowupPicker.min = this.value;
                                            // If the current next_followup is before the new followup, clear it
                                            if (nextFollowupPicker.value && nextFollowupPicker.value < this.value) {
                                                nextFollowupPicker.value = '';
                                                // Optionally trigger its change event to save the cleared value immediately
                                                nextFollowupPicker.dispatchEvent(new Event('change', {
                                                    bubbles: true
                                                }));
                                            }
                                        } else {
                                            // If followup date is cleared, remove the restriction
                                            nextFollowupPicker.removeAttribute('min');
                                        }
                                    });
                                });

                                document.body.addEventListener('mouseout', function(event) {
                                    if (event.target.classList.contains('history-icon')) {
                                        popover.style.display = 'none';
                                    }
                                });
                            });


                            function fetchBatchesForUser(userId, targetBatchDivId, targetBatchSelectId) {
                                const batchDiv = document.getElementById(targetBatchDivId);
                                const batchSelect = document.getElementById(targetBatchSelectId);

                                // If no user is selected or 'team' is selected, hide the batch dropdown
                                if (!userId || userId === 'team') {
                                    batchDiv.style.display = 'none';
                                    batchSelect.innerHTML = ''; // Clear previous options
                                    return;
                                }

                                // Show the batch div (it might be hidden)
                                batchDiv.style.display = 'block';
                                batchSelect.innerHTML = '<option value="">Loading batches...</option>'; // Show loading indicator
                                batchSelect.disabled = true;

                                const formData = new FormData();
                                formData.append('get_batches_for_user', true);
                                formData.append('user_id', userId);

                                fetch('index.php', {
                                        method: 'POST',
                                        body: formData
                                    })
                                    .then(response => response.json())
                                    .then(data => {
                                        batchSelect.innerHTML = ''; // Clear loading message
                                        batchSelect.disabled = false;

                                        // Add an "All Batches" option as the default
                                        batchSelect.add(new Option('-- All Batches --', ''));

                                        if (data.status === 'success' && data.batches.length > 0) {
                                            data.batches.forEach(batchName => {
                                                batchSelect.add(new Option(batchName, batchName));
                                            });
                                        } else {
                                            // You can add a disabled option if no batches are found
                                            const noBatchOption = new Option('No batches found for this user', '');
                                            noBatchOption.disabled = true;
                                            batchSelect.add(noBatchOption);
                                        }
                                    })
                                    .catch(error => {
                                        console.error('Error fetching batches:', error);
                                        batchSelect.innerHTML = '<option value="">Error loading</option>';
                                    });
                            }

                            const printUserSelect = document.getElementById('print_report_user');
                            if (printUserSelect) {
                                printUserSelect.addEventListener('change', function() {
                                    fetchBatchesForUser(this.value, 'print_batch_selection_div', 'print_report_batch_file');
                                });
                                // Trigger on page load in case a user is pre-selected (e.g., for 'member' role)
                                fetchBatchesForUser(printUserSelect.value, 'print_batch_selection_div', 'print_report_batch_file');
                            }

                            const excelUserSelect = document.getElementById('excel_report_user');
                            if (excelUserSelect) {
                                excelUserSelect.addEventListener('change', function() {
                                    fetchBatchesForUser(this.value, 'excel_batch_selection_div', 'excel_report_batch_file');
                                });
                                // Trigger on page load
                                fetchBatchesForUser(excelUserSelect.value, 'excel_batch_selection_div', 'excel_report_batch_file');
                            }


                            function togglePasswordVisibility(fieldId, iconElement) {
                                const input = document.getElementById(fieldId);
                                if (input.type === "password") {
                                    input.type = "text";
                                    iconElement.classList.remove('fa-eye');
                                    iconElement.classList.add('fa-eye-slash');
                                } else {
                                    input.type = "password";
                                    iconElement.classList.remove('fa-eye-slash');
                                    iconElement.classList.add('fa-eye');
                                }
                            }

                            // document.addEventListener("contextmenu", (e) => e.preventDefault());
                            // document.addEventListener("keydown", (e) => {
                            //     if (e.key === "F12" || (e.ctrlKey && e.shiftKey && ["I", "J"].includes(e.key)) || (e.ctrlKey && e.key === "U")) {
                            //         e.preventDefault();
                            //     }
                            // });
                        </script>


                        <?php
                        // This entire script block is only added to the page if the user is logged in.
                        if (isset($_SESSION['otp_verified']) && isset($_SESSION['login_log_id'])): // Also check if log_id exists
                        ?>
                            <script>
                                // =================================================================
                                // AUTO-LOGOUT FOR INACTIVITY (CLIENT-SIDE) - MODIFIED
                                // =================================================================
                                (function() {
                                    const timeoutDuration = <?php echo SESSION_TIMEOUT * 1000; ?>; // Get timeout from PHP constant
                                    let inactivityTimer;

                                    function logoutUser() {
                                        // MODIFIED: Pass the login_log_id in the URL.
                                        // This ensures the server knows which record to update even if the session has expired.
                                        window.location.href = '?logout=true&reason=inactive&log_id=<?php echo $_SESSION['login_log_id']; ?>';
                                    }

                                    function resetInactivityTimer() {
                                        clearTimeout(inactivityTimer);
                                        inactivityTimer = setTimeout(logoutUser, timeoutDuration);
                                    }

                                    const activityEvents = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'];
                                    activityEvents.forEach(function(eventName) {
                                        document.addEventListener(eventName, resetInactivityTimer, true);
                                    });

                                    // Start the timer
                                    resetInactivityTimer();
                                })();
                            </script>
                        <?php endif; ?>

</body>

</html>
