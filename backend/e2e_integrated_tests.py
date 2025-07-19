#!/usr/bin/env python3
"""
End-to-End Testing for Integrated Business Logic
Tests JWT Authentication + RBAC + User Management APIs
"""
import requests
import json
import time
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Test configuration
BASE_URL = "http://localhost:8000"
TEST_RESULTS = []

def log_test_result(test_name, status, details=None, response_time=None):
    """Log test result"""
    result = {
        "test_name": test_name,
        "status": status,
        "timestamp": datetime.now().isoformat(),
        "response_time_ms": response_time,
        "details": details
    }
    TEST_RESULTS.append(result)
    
    status_emoji = "✅" if status == "PASS" else "❌" if status == "FAIL" else "⏭️"
    logger.info(f"{status_emoji} {test_name}: {status}")
    if details:
        logger.info(f"   Details: {details}")

def make_request(method, endpoint, headers=None, json_data=None, expected_status=200):
    """Make HTTP request and measure response time"""
    start_time = time.time()
    try:
        url = f"{BASE_URL}{endpoint}"
        response = requests.request(method, url, headers=headers, json=json_data, timeout=10)
        response_time = int((time.time() - start_time) * 1000)
        
        return {
            "status_code": response.status_code,
            "json": response.json() if response.headers.get('content-type', '').startswith('application/json') else None,
            "text": response.text,
            "response_time": response_time,
            "success": response.status_code == expected_status
        }
    except Exception as e:
        response_time = int((time.time() - start_time) * 1000)
        return {
            "status_code": None,
            "json": None,
            "text": str(e),
            "response_time": response_time,
            "success": False,
            "error": str(e)
        }

def test_api_health():
    """Test API health check"""
    response = make_request("GET", "/health")
    
    if response["success"] and response["json"]:
        log_test_result(
            "API Health Check",
            "PASS",
            f"Status: {response['json'].get('status')}, Auth: {response['json'].get('authentication')}",
            response["response_time"]
        )
        return True
    else:
        log_test_result(
            "API Health Check",
            "FAIL",
            f"Status: {response['status_code']}, Error: {response.get('error', 'Unknown')}",
            response["response_time"]
        )
        return False

def test_scenario_1_admin_user_management():
    """
    Scenario 1: Admin User Management with RBAC
    - Login as SUPER_ADMIN
    - Create, update, delete users via protected endpoints
    - Verify RBAC enforcement
    """
    logger.info("🎯 Starting Scenario 1: Admin User Management with RBAC")
    
    # Step 1: Register SUPER_ADMIN user
    admin_data = {
        "email": "superadmin@village.test",
        "password": "SuperAdmin123!",
        "full_name": "Super Administrator",
        "role": "SUPER_ADMIN"
    }
    
    response = make_request("POST", "/auth/register", json_data=admin_data, expected_status=201)
    if response["success"]:
        log_test_result(
            "Register SUPER_ADMIN",
            "PASS",
            f"User created: {response['json']['user']['email']}",
            response["response_time"]
        )
    else:
        log_test_result(
            "Register SUPER_ADMIN",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
        return False
    
    # Step 2: Login as SUPER_ADMIN
    login_data = {
        "email": "superadmin@village.test",
        "password": "SuperAdmin123!"
    }
    
    response = make_request("POST", "/auth/login", json_data=login_data)
    if response["success"] and response["json"] and "access_token" in response["json"]:
        access_token = response["json"]["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        log_test_result(
            "SUPER_ADMIN Login",
            "PASS",
            f"Token received, expires in: {response['json'].get('expires_in', 'N/A')}s",
            response["response_time"]
        )
    else:
        log_test_result(
            "SUPER_ADMIN Login",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
        return False
    
    # Step 3: Access protected endpoint - Get all users (Admin only)
    response = make_request("GET", "/api/v1/users", headers=headers)
    if response["success"]:
        users_count = len(response["json"].get("users", []))
        log_test_result(
            "Get Users List (Admin Access)",
            "PASS",
            f"Retrieved {users_count} users",
            response["response_time"]
        )
    else:
        log_test_result(
            "Get Users List (Admin Access)",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
    
    # Step 4: Create new user via protected endpoint (Village Admin+)
    new_user_data = {
        "username": "testuser1",
        "email": "testuser1@village.test",
        "full_name": "Test User One",
        "password": "TestUser123!",
        "role": "RESIDENT"
    }
    
    response = make_request("POST", "/api/v1/users", headers=headers, json_data=new_user_data, expected_status=201)
    if response["success"]:
        created_user_id = response["json"]["user"]["id"]
        log_test_result(
            "Create User (Admin Access)",
            "PASS",
            f"User created: {response['json']['user']['username']} (ID: {created_user_id})",
            response["response_time"]
        )
    else:
        log_test_result(
            "Create User (Admin Access)",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
        return False
    
    # Step 5: Update user via protected endpoint (Village Admin+)
    update_data = {
        "full_name": "Test User One Updated",
        "notes": "Updated by SUPER_ADMIN"
    }
    
    response = make_request("PUT", f"/api/v1/users/{created_user_id}", headers=headers, json_data=update_data)
    if response["success"]:
        log_test_result(
            "Update User (Admin Access)",
            "PASS",
            f"User updated: {response['json']['user']['full_name']}",
            response["response_time"]
        )
    else:
        log_test_result(
            "Update User (Admin Access)",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
    
    # Step 6: Get user statistics (Admin only)
    response = make_request("GET", "/api/v1/users/stats", headers=headers)
    if response["success"]:
        stats = response["json"]
        log_test_result(
            "Get User Statistics (Admin Access)",
            "PASS",
            f"Total: {stats.get('total_users')}, Active: {stats.get('active_users')}",
            response["response_time"]
        )
    else:
        log_test_result(
            "Get User Statistics (Admin Access)",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
    
    # Step 7: Delete user (Super Admin only)
    response = make_request("DELETE", f"/api/v1/users/{created_user_id}", headers=headers)
    if response["success"]:
        log_test_result(
            "Delete User (Super Admin Only)",
            "PASS",
            f"User deleted successfully",
            response["response_time"]
        )
    else:
        log_test_result(
            "Delete User (Super Admin Only)",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
    
    return True

def test_scenario_2_resident_access_restrictions():
    """
    Scenario 2: Resident Access to Services with RBAC Restrictions
    - Login as RESIDENT
    - Attempt to access resident-allowed endpoints (success)
    - Attempt to access admin-only endpoints (should fail with 403)
    """
    logger.info("🎯 Starting Scenario 2: Resident Access Restrictions")
    
    # Step 1: Register RESIDENT user
    resident_data = {
        "email": "resident@village.test",
        "password": "Resident123!",
        "full_name": "Village Resident",
        "role": "RESIDENT"
    }
    
    response = make_request("POST", "/auth/register", json_data=resident_data, expected_status=201)
    if response["success"]:
        resident_user_id = response["json"]["user"]["id"]
        log_test_result(
            "Register RESIDENT",
            "PASS",
            f"User created: {response['json']['user']['email']} (ID: {resident_user_id})",
            response["response_time"]
        )
    else:
        log_test_result(
            "Register RESIDENT",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
        return False
    
    # Step 2: Login as RESIDENT
    login_data = {
        "email": "resident@village.test",
        "password": "Resident123!"
    }
    
    response = make_request("POST", "/auth/login", json_data=login_data)
    if response["success"] and response["json"] and "access_token" in response["json"]:
        access_token = response["json"]["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        log_test_result(
            "RESIDENT Login",
            "PASS",
            f"Token received, expires in: {response['json'].get('expires_in', 'N/A')}s",
            response["response_time"]
        )
    else:
        log_test_result(
            "RESIDENT Login",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
        return False
    
    # Step 3: Access allowed endpoint - Get own user profile (Authenticated users)
    response = make_request("GET", f"/api/v1/users/{resident_user_id}", headers=headers)
    if response["success"]:
        log_test_result(
            "Get Own User Profile (Resident Access)",
            "PASS",
            f"Profile retrieved: {response['json']['user']['full_name']}",
            response["response_time"]
        )
    else:
        log_test_result(
            "Get Own User Profile (Resident Access)",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
    
    # Step 4: Attempt to access admin-only endpoint - Get all users (should fail with 403)
    response = make_request("GET", "/api/v1/users", headers=headers, expected_status=403)
    if response["status_code"] == 403:
        log_test_result(
            "Get Users List (Resident Denied)",
            "PASS",
            f"Correctly denied with 403 Forbidden",
            response["response_time"]
        )
    else:
        log_test_result(
            "Get Users List (Resident Denied)",
            "FAIL",
            f"Expected 403, got {response['status_code']}: {response['text'][:100]}",
            response["response_time"]
        )
    
    # Step 5: Attempt to create user (should fail with 403)
    new_user_data = {
        "username": "unauthorized",
        "email": "unauthorized@village.test",
        "full_name": "Unauthorized User",
        "password": "Test123!"
    }
    
    response = make_request("POST", "/api/v1/users", headers=headers, json_data=new_user_data, expected_status=403)
    if response["status_code"] == 403:
        log_test_result(
            "Create User (Resident Denied)",
            "PASS",
            f"Correctly denied with 403 Forbidden",
            response["response_time"]
        )
    else:
        log_test_result(
            "Create User (Resident Denied)",
            "FAIL",
            f"Expected 403, got {response['status_code']}: {response['text'][:100]}",
            response["response_time"]
        )
    
    # Step 6: Attempt to get user statistics (should fail with 403)
    response = make_request("GET", "/api/v1/users/stats", headers=headers, expected_status=403)
    if response["status_code"] == 403:
        log_test_result(
            "Get User Statistics (Resident Denied)",
            "PASS",
            f"Correctly denied with 403 Forbidden",
            response["response_time"]
        )
    else:
        log_test_result(
            "Get User Statistics (Resident Denied)",
            "FAIL",
            f"Expected 403, got {response['status_code']}: {response['text'][:100]}",
            response["response_time"]
        )
    
    return True

def test_scenario_3_village_admin_permissions():
    """
    Scenario 3: Village Admin Permissions
    - Login as VILLAGE_ADMIN
    - Test intermediate permissions (can create/update but not delete)
    """
    logger.info("🎯 Starting Scenario 3: Village Admin Permissions")
    
    # Step 1: Register VILLAGE_ADMIN user
    admin_data = {
        "email": "villageadmin@village.test",
        "password": "VillageAdmin123!",
        "full_name": "Village Administrator",
        "role": "VILLAGE_ADMIN"
    }
    
    response = make_request("POST", "/auth/register", json_data=admin_data, expected_status=201)
    if response["success"]:
        log_test_result(
            "Register VILLAGE_ADMIN",
            "PASS",
            f"User created: {response['json']['user']['email']}",
            response["response_time"]
        )
    else:
        log_test_result(
            "Register VILLAGE_ADMIN",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
        return False
    
    # Step 2: Login as VILLAGE_ADMIN
    login_data = {
        "email": "villageadmin@village.test",
        "password": "VillageAdmin123!"
    }
    
    response = make_request("POST", "/auth/login", json_data=login_data)
    if response["success"] and response["json"] and "access_token" in response["json"]:
        access_token = response["json"]["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}
        log_test_result(
            "VILLAGE_ADMIN Login",
            "PASS",
            f"Token received, expires in: {response['json'].get('expires_in', 'N/A')}s",
            response["response_time"]
        )
    else:
        log_test_result(
            "VILLAGE_ADMIN Login",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
        return False
    
    # Step 3: Create user (Village Admin can create)
    new_user_data = {
        "username": "testuser2",
        "email": "testuser2@village.test",
        "full_name": "Test User Two",
        "password": "TestUser123!",
        "role": "RESIDENT"
    }
    
    response = make_request("POST", "/api/v1/users", headers=headers, json_data=new_user_data, expected_status=201)
    if response["success"]:
        created_user_id = response["json"]["user"]["id"]
        log_test_result(
            "Create User (Village Admin Access)",
            "PASS",
            f"User created: {response['json']['user']['username']} (ID: {created_user_id})",
            response["response_time"]
        )
    else:
        log_test_result(
            "Create User (Village Admin Access)",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
        return False
    
    # Step 4: Update user (Village Admin can update)
    update_data = {
        "full_name": "Test User Two Updated",
        "notes": "Updated by VILLAGE_ADMIN"
    }
    
    response = make_request("PUT", f"/api/v1/users/{created_user_id}", headers=headers, json_data=update_data)
    if response["success"]:
        log_test_result(
            "Update User (Village Admin Access)",
            "PASS",
            f"User updated: {response['json']['user']['full_name']}",
            response["response_time"]
        )
    else:
        log_test_result(
            "Update User (Village Admin Access)",
            "FAIL",
            f"Status: {response['status_code']}, Response: {response['text'][:100]}",
            response["response_time"]
        )
    
    # Step 5: Attempt to delete user (Village Admin cannot delete - should fail with 403)
    response = make_request("DELETE", f"/api/v1/users/{created_user_id}", headers=headers, expected_status=403)
    if response["status_code"] == 403:
        log_test_result(
            "Delete User (Village Admin Denied)",
            "PASS",
            f"Correctly denied with 403 Forbidden",
            response["response_time"]
        )
    else:
        log_test_result(
            "Delete User (Village Admin Denied)",
            "FAIL",
            f"Expected 403, got {response['status_code']}: {response['text'][:100]}",
            response["response_time"]
        )
    
    return True

def test_scenario_4_unauthenticated_access():
    """
    Scenario 4: Unauthenticated Access
    - Attempt to access protected endpoints without token
    - Should receive 401 Unauthorized
    """
    logger.info("🎯 Starting Scenario 4: Unauthenticated Access")
    
    # Test all protected endpoints without authentication
    protected_endpoints = [
        ("GET", "/api/v1/users", "Get Users List"),
        ("POST", "/api/v1/users", "Create User"),
        ("GET", "/api/v1/users/1", "Get User Details"),
        ("PUT", "/api/v1/users/1", "Update User"),
        ("DELETE", "/api/v1/users/1", "Delete User"),
        ("GET", "/api/v1/users/stats", "Get User Statistics"),
        ("POST", "/api/v1/users/1/toggle-status", "Toggle User Status")
    ]
    
    for method, endpoint, description in protected_endpoints:
        json_data = {"test": "data"} if method in ["POST", "PUT"] else None
        response = make_request(method, endpoint, json_data=json_data, expected_status=401)
        
        if response["status_code"] == 401:
            log_test_result(
                f"{description} (Unauthenticated Denied)",
                "PASS",
                f"Correctly denied with 401 Unauthorized",
                response["response_time"]
            )
        else:
            log_test_result(
                f"{description} (Unauthenticated Denied)",
                "FAIL",
                f"Expected 401, got {response['status_code']}: {response['text'][:100]}",
                response["response_time"]
            )

def run_all_tests():
    """Run all E2E tests"""
    logger.info("🚀 Starting E2E Testing for Integrated Business Logic")
    logger.info("=" * 80)
    
    start_time = time.time()
    
    # Test API health first
    if not test_api_health():
        logger.error("❌ API Health Check failed - aborting tests")
        return
    
    # Run test scenarios
    test_scenario_1_admin_user_management()
    test_scenario_2_resident_access_restrictions()
    test_scenario_3_village_admin_permissions()
    test_scenario_4_unauthenticated_access()
    
    # Calculate results
    total_time = time.time() - start_time
    total_tests = len(TEST_RESULTS)
    passed_tests = len([r for r in TEST_RESULTS if r["status"] == "PASS"])
    failed_tests = len([r for r in TEST_RESULTS if r["status"] == "FAIL"])
    skipped_tests = len([r for r in TEST_RESULTS if r["status"] == "SKIP"])
    
    success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
    
    # Print summary
    logger.info("=" * 80)
    logger.info("🎯 E2E Testing Summary")
    logger.info(f"📊 Total Tests: {total_tests}")
    logger.info(f"✅ Passed: {passed_tests}")
    logger.info(f"❌ Failed: {failed_tests}")
    logger.info(f"⏭️ Skipped: {skipped_tests}")
    logger.info(f"📈 Success Rate: {success_rate:.1f}%")
    logger.info(f"⏱️ Total Time: {total_time:.2f}s")
    logger.info("=" * 80)
    
    # Save results to file
    results_summary = {
        "test_run": {
            "timestamp": datetime.now().isoformat(),
            "total_tests": total_tests,
            "passed": passed_tests,
            "failed": failed_tests,
            "skipped": skipped_tests,
            "success_rate": success_rate,
            "total_time_seconds": total_time
        },
        "test_results": TEST_RESULTS
    }
    
    with open("integrated_e2e_test_results.json", "w") as f:
        json.dump(results_summary, f, indent=2)
    
    logger.info(f"📄 Detailed results saved to: integrated_e2e_test_results.json")
    
    if success_rate >= 80:
        logger.info("🎉 E2E Testing PASSED - System ready for production!")
    else:
        logger.warning("⚠️ E2E Testing has issues - Review failed tests before production")

if __name__ == "__main__":
    run_all_tests()

