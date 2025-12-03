import vt
import time 
import threading
import os
import math
def check_virustotal(API , url):
    try:
        client = vt.Client(API, timeout=60)
        analysis_report = client.get_object(f"/urls/{vt.url_id(url)}")
        stats = analysis_report.last_analysis_stats
        malicious = stats.get("malicious", 0)

        if malicious < 3:
            print(f"url: {url} la url can kiem tra lai : {malicious}")
            return False
        else:
            print(f"url: {url} la url nguy hiem : {malicious}")
            return True
    except vt.error.APIError as e:
        print(f"LỖI API: {e}")
        return False
    except Exception as e:
        print("LỖI KẾT NỐI hoặc LỖI KHÁC:")
        print(e)
    finally:
        if 'client' in locals():
            client.close()

def read_lines_from_txt(file_path , API , path_out, path_re):
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                content = line.strip()

                if content: 
                    if check_virustotal(API , content):
                        with open(path_out, 'a', encoding='utf-8') as file_out:
                            file_out.write(content + "\n")
                    else: 
                        with open(path_re, 'a', encoding='utf-8') as file_out:
                            file_out.write(content + "\n")
                    time.sleep(20)
    except FileNotFoundError:
        print(f"Lỗi: Không tìm thấy file tại đường dẫn: {file_path}")
    except Exception as e:
        print(f"Lỗi xảy ra trong quá trình đọc file: {e}")
if __name__ == "__main__":
    print("================================================================================")
    print("=========================TOOL AUTO CHECK URL VIRUSTOTAL=========================")
    print("================================================================================")
    
    apikeys_input = input("Nhap APIKEY theo dang api-api-...\n")
    apikeys_input_array = apikeys_input.split("-")

    so_luong_api_key = len(apikeys_input_array)

    try:
        directory_current = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        print("LƯU Ý: Không thể xác định thư mục. Đang sử dụng thư mục làm việc hiện tại.")
        directory_current = os.getcwd()

    PATH_FILE_INPUT = os.path.join(directory_current, "input.txt")
    urls = []
    try:
        with open(PATH_FILE_INPUT, 'r', encoding='utf-8') as fr:
            for line in fr:
                url = line.strip()
                if url:
                    urls.append(url)
        print(f"Đã đọc thành công {len(urls)} URL từ {PATH_FILE_INPUT}")
    except FileNotFoundError:
        print(f"LỖI: Không tìm thấy file input tại: {PATH_FILE_INPUT}. Vui lòng kiểm tra lại.")
        exit()
        
    tong_so_luong = len(urls)
    
    if tong_so_luong == 0:
        print("Cảnh báo: File input.txt không có URL nào. Bỏ qua việc chia file.")
        exit()

    kich_thuoc_moi_phan = math.ceil(tong_so_luong / so_luong_api_key)
    print(f"Tổng số URL: {tong_so_luong}. Số API Key: {so_luong_api_key}. Kích thước mỗi phần (khoảng): {kich_thuoc_moi_phan} URL.")
    list_path_input_da_chia = []

    for i in range(so_luong_api_key):
        start_index = i * kich_thuoc_moi_phan
        end_index = start_index + kich_thuoc_moi_phan
        phan_urls_chia = urls[start_index:end_index] 
        file_index = i + 1 
        path_file_input_chia = os.path.join(directory_current, f"input{file_index}.txt")
        
        with open(path_file_input_chia, 'w', encoding='utf-8') as fw:
            fw.write('\n'.join(phan_urls_chia))
            if phan_urls_chia:
                fw.write('\n')
        
        print(f"Đã tạo file {path_file_input_chia} với {len(phan_urls_chia)} URL.")
        list_path_input_da_chia.append(path_file_input_chia)

    print("\n--- BẮT ĐẦU CHECK ---")
    threads = []
    for index, api_key_value in enumerate(apikeys_input_array):
        file_index = index + 1
        PATH_INPUT = list_path_input_da_chia[index] 
        PATH_OUTPUT = os.path.join(directory_current, f"output{file_index}.txt")
        PATH_RE = os.path.join(directory_current, f"re{file_index}.txt")
        thread = threading.Thread(
            target=read_lines_from_txt,
            args=(PATH_INPUT , api_key_value , PATH_OUTPUT , PATH_RE), 
            name="Auto 1"
        )
        threads.append(thread)
        thread.start()
    for th in threads:
        th.join()
    PATH_FILE_OUTPUT = os.path.join(directory_current, "output.txt")
    PATH_FILE_RE = os.path.join(directory_current, "re.txt")
    if os.path.exists(PATH_FILE_OUTPUT): os.remove(PATH_FILE_OUTPUT)
    if os.path.exists(PATH_FILE_RE): os.remove(PATH_FILE_RE)
    with open(PATH_FILE_OUTPUT, 'a', encoding='utf-8') as file_out_results:
        for index, api_key_value in enumerate(apikeys_input_array):
            file_index = index + 1
            PATH_OUTPUT = os.path.join(directory_current, f"output{file_index}.txt")
            try:
                with open(PATH_OUTPUT, 'r', encoding='utf-8') as fr:
                    file_out_results.write(fr.read())    
            except FileNotFoundError:
                print(f"next")
    with open(PATH_FILE_RE, 'a', encoding='utf-8') as file_out_results:
        for index, api_key_value in enumerate(apikeys_input_array):
            file_index = index + 1
            PATH_RE = os.path.join(directory_current, f"re{file_index}.txt")
            try:
                with open(PATH_RE, 'r', encoding='utf-8') as fr:
                    file_out_results.write(fr.read())   
            except FileNotFoundError:
                print(f"next")
    print("===============KET THUC AUTO TOOL==============================")
    exit()
# 23804a7b88aa86d3f1de229623f6db7a1bdb07dbd7f27e5ca3f8876e9c6c6593-df64d7ab2f2bfebd316094c20fc70cfa62339bb136691c5e5e851f72130bdddf-5b9f7e7b664be737ccc40daa9ff00da0f05b61a79645be981c08a486e0e6861a-28a2685c82940932bfe35357e34156fa07ab20cbc0acfc313e7920108f024318-c3e748d995192d26f49104fbb004a8d7d104aacf5f0a4a9d8afc9f46f4efaeb0-8810bd58a8846d80ec4cd0213d885253e5d905f8469e46e94638f5cbf61c9e53-0be6240a7bb26e16048a9d98c23cd15d786729c15facf49b430e5784fcee2683-72986c39060bbd617197808217238b2628410173b9b572931cf27c13b0e95edb
