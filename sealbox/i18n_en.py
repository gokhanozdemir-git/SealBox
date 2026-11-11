"""English translations, keyed by the Turkish source text; ``{}`` stands for a variable.

``tests/test_i18n.py`` catches missing and unused keys.
"""

from __future__ import annotations

EN: dict[str, str] = {
    # --- Approval and secret dialogs (approval.py) --------------------------------------
    "{} için kasadaki gizli değerler isteniyor.": "{} is requesting secret values from the vault.",
    "Komut:": "Command:",
    "GİZLİ": "REDACTED",
    "Klasör: {}": "Folder: {}",
    "Verilecek değerler: {}": "Values to hand over: {}",
    "Bu komutu siz başlatmadıysanız Reddet'e basın.": "If you did not start this command, press Deny.",
    " (+{} tane daha)": " (+{} more)",
    "kasa onayı": "vault approval",
    "İzin ver": "Allow",
    "Reddet": "Deny",
    "Kullanıcı onay vermedi; kasa açılmadı": "Not approved by the user; the vault was not opened",
    "dışarı gönderiyor": "sends it out",
    "dosyaya yazıyor": "writes it to a file",
    "dönüştürüp yazdırıyor": "prints it disguised",
    "yazdırıyor": "prints it",
    "İlk çalıştırma: bundan sonra, değişen riskli satırlar burada gösterilir.": (
        "First run: from now on, risky lines that changed will be shown here."
    ),
    "Son onaydan beri sırları dışarı çıkarabilecek bir değişiklik yok.": (
        "Nothing that could leak secrets has changed since the last approval."
    ),
    "⚠ Son onaydan beri {} dosyada riskli değişiklik var:": (
        "⚠ Risky changes in {} file(s) since the last approval:"
    ),
    "Son onaydan beri {} dosyada sır yazdıran satır eklendi:": (
        "Lines that print secrets were added in {} file(s) since the last approval:"
    ),
    "        (+{} satır daha)": "        (+{} more lines)",
    "(+{} dosya daha)": "(+{} more files)",
    (
        "Ağa gönderilen veya dosyaya yazılan değeri SealBox gizleyemez. Ekrana yazılanı gizler, "
        "ama dönüştürülmüşse (base64, ters çevrilmiş) tanımayabilir. Bu değişiklikleri siz "
        "yapmadıysanız Reddet'e basıp dosyalara bakın."
    ): (
        "SealBox cannot hide a value sent over the network or written to a file. It hides "
        "what is printed, but may miss it if transformed (base64, reversed). If you did not "
        "make these changes, press Deny and look at the files."
    ),
    "Kaydettim": "I saved it",
    "Vazgeç": "Cancel",
    "Tamam": "OK",
    "Kaydettiğini doğrulamak için:": "To confirm you saved it:",
    "Yazdığın, gösterilenle uyuşmuyor. Tekrar bak.": "What you typed does not match. Look again.",
    # --- Configuration -----------------------------------------------------------------
    "Yapılandırma geçersiz: {}": "Invalid configuration: {}",
    "Yapılandırma dosyası okunamadı (satır {})": "Could not read the configuration file (line {})",
    # --- Cryptography ------------------------------------------------------------------
    "AES-256 anahtarı 32 bayt olmalı": "An AES-256 key must be 32 bytes",
    "Anahtar başına şifreleme sınırı aşıldı; anahtarı yenileyin": (
        "Per-key encryption limit reached; rotate the key"
    ),
    "Şifreli veri biçimi geçersiz": "Invalid encrypted data format",
    "Şifre çözme başarısız: veri değiştirilmiş veya anahtar yanlış": (
        "Decryption failed: the data was modified or the key is wrong"
    ),
    "Argon2id tuzu en az 16 bayt olmalı": "The Argon2id salt must be at least 16 bytes",
    "Kurtarma sırrı 16 bayt olmalı": "The recovery secret must be 16 bytes",
    "Kurtarma kodu 8 grup × 4 harf olmalı": "A recovery code is 8 groups × 4 characters",
    "Kurtarma kodunda yazım hatası var": "The recovery code has a typo",
    "X25519 gizli anahtarı 32 bayt olmalı": "An X25519 private key must be 32 bytes",
    "Geçersiz açık anahtar": "Invalid public key",
    "Kilitli anahtar biçimi geçersiz": "Invalid wrapped key format",
    "ed25519 açık anahtarı 32 bayt olmalı": "An ed25519 public key must be 32 bytes",
    "Geçersiz ed25519 açık anahtarı": "Invalid ed25519 public key",
    "RSA anahtarı en az {} bit olmalı": "RSA keys must be at least {} bits",
    "Şifre çözme başarısız: anahtar yanlış veya veri değiştirilmiş": (
        "Decryption failed: the key is wrong or the data was modified"
    ),
    "{} (ayrıntılar güvenlik nedeniyle gizlendi)": "{} (details hidden for security)",
    "Bu {} sealbox'ın daha yeni bir sürümüyle yazılmış; sealbox'ı güncelleyin "
    "(pipx upgrade sealbox)": (
        "This {} was written by a newer version of sealbox; please upgrade (pipx upgrade sealbox)"
    ),
    "kasa": "vault",
    "kurtarma dosyası": "recovery file",
    # --- Key sharing ---------------------------------------------------------------------
    "Parçalar reddedildi: bozuk, eksik ya da farklı anahtarlara ait": (
        "Shares rejected: corrupted, incomplete or from different keys"
    ),
    "Paylaşılacak anahtar 16 veya 32 bayt olmalı": "The key to split must be 16 or 32 bytes",
    "Geçersiz parça sayısı": "Invalid number of shares",
    "Yetersiz parça: {} benzersiz parça var, en az {} gerekli": (
        "Not enough shares: {} unique, at least {} needed"
    ),
    "En fazla {} parça verilebilir": "At most {} shares can be given",
    "Parça kodunda geçersiz harf var": "The share code contains an invalid character",
    "Parça geçersiz": "Invalid share",
    "Parça kodunda yazım hatası var": "The share code has a typo",
    # --- Vault -----------------------------------------------------------------------------
    "Bilinmeyen yer tutucu": "Unknown placeholder",
    "Ortam değişkeni adı başka bir kayda bağlı": (
        "The environment variable name is bound to another entry"
    ),
    "Vault kaydı geçersiz": "Invalid vault entry",
    "Kasa anahtarı bu bilgisayarın kimlik deposunda bulunamadı": (
        "The vault key was not found in this computer's credential store"
    ),
    "Bu proje için kurtarma kopyası var: 'sealbox recovery restore'": (
        "A recovery copy exists for this project: 'sealbox recovery restore'"
    ),
    "Kurtarma kodun ve kitin varsa: 'sealbox recovery restore --kit DOSYA'": (
        "If you have your recovery code and kit: 'sealbox recovery restore --kit FILE'"
    ),
    " Ekipteysen: bu bilgisayarın SSH anahtarını GitHub'a ekle ve bir sahibe 'team add' yaptır.": (
        " If you are on a team: add this computer's SSH key to GitHub and ask an owner to run "
        "'team add'."
    ),
    "{}. {}.{} Hiçbiri yoksa: 'sealbox vault reset'": "{}. {}.{} If you have none: 'sealbox vault reset'",
    "kasası var": "has a vault",
    "git deposunun kökü": "is the root of the git repository",
    "{} dosyası var": "has a {} file",
    "Bu projede kasa yok; önce 'seal' çalıştırın": "This project has no vault; run 'seal' first",
    "İşletim sistemi kimlik deposuna erişilemedi": "Could not access the OS credential store",
    "İşletim sistemi kimlik deposuna yazılamadı": "Could not write to the OS credential store",
    "Kasa anahtarı bozuk": "The vault key is corrupted",
    # --- Recovery ----------------------------------------------------------------------
    "Parçalar mevcut kurtarma kodundan üretilir.": "Shares are made from your current recovery code.",
    "şifre yöneticine": "in your password manager",
    "kağıda yazıp evde bir yere": "on paper somewhere at home",
    "güvendiğin birine": "with someone you trust",
    "Proje kimliği bozuk": "The project id is corrupted",
    "Kurtarma dosyası bozuk: {}": "Recovery file is corrupted: {}",
    "Kurtarma zaten kurulu. Yeni kod için: recovery setup --new (eski kodla yapılan kopyalar "
    "projeler açıldıkça yenilenir)": (
        "Recovery is already set up. For a new code: recovery setup --new (copies made with the "
        "old code are renewed as projects are opened)"
    ),
    "Kurtarma kodu": "Recovery code",
    "Kurtarma kodu girilmedi": "No recovery code was entered",
    "Kurtarma kodunu yaz (XXXX-XXXX-...):": "Type your recovery code (XXXX-XXXX-...):",
    "Tanınmadı: kurtarma kodu 8 grup × 4 harf, her parça 10 grup × 4 harf olmalı": (
        "Not recognised: a recovery code is 8 groups × 4 characters, each share 10 groups × 4"
    ),
    "En az {} farklı parça gerekli": "At least {} different shares are needed",
    "Kasayı kurtar": "Recover the vault",
    "Kurtarma kodunu yaz (8 grup: XXXX-XXXX-...)\n"
    "ya da elindeki 2 kurtarma parçasını (10'ar grup) alt alta yaz:": (
        "Type your recovery code (8 groups: XXXX-XXXX-...)\n"
        "or type your 2 recovery shares (10 groups each) one below the other:"
    ),
    "Hedef dosya zaten var; üzerine yazılmaz": "The target file already exists; it is not overwritten",
    "Bu dosya bir kurtarma kiti değil": "This file is not a recovery kit",
    "Kit başka bir projeye ait": "The kit belongs to another project",
    "Kurtarma kodu bu kasaya ait değil (yanlış kod ya da eski kod)": (
        "The recovery code does not belong to this vault (wrong or old code)"
    ),
    "Bu bilgisayarda kurtarma kurulmamış ('recovery setup')": (
        "Recovery is not set up on this computer ('recovery setup')"
    ),
    "Kurtarma kodu yanlış": "Wrong recovery code",
    "Kod kaydedilmedi; kurtarma kurulmadı": "The code was not saved; recovery was not set up",
    "Parçalar kaydedilmedi; yeniden üretin": "The shares were not saved; generate them again",
    "Kelimeli parçaların her biri {} kelime olmalı": "Each word share must have {} words",
    "Bu proje için bu bilgisayarda kurtarma kopyası yok. Kurtarma kitin varsa: recovery restore "
    "--kit DOSYA": (
        "No recovery copy for this project on this computer. If you have a recovery kit: "
        "recovery restore --kit FILE"
    ),
    "Kurtarılan anahtar bu kasayı açmıyor (kasa sonradan yenilenmiş)": (
        "The recovered key does not open this vault (the vault was re-keyed later)"
    ),
    "Önce kurtarma kur: recovery setup": "Set up recovery first: recovery setup",
    "Kurtarma kaydı bozuk": "The recovery record is corrupted",
    "Bu kod kasa anahtarın kaybolursa (Windows sıfırlama, yeni bilgisayar) kasalarını geri açar. "
    "Kağıda yaz ya da şifre yöneticine kaydet. Bir daha GÖSTERİLMEYECEK; bizde de kopyası yok.": (
        "This code reopens your vaults if your vault key is lost (Windows reset, new computer). "
        "Write it on paper or save it in your password manager. It will NOT be shown again; we "
        "keep no copy."
    ),
    "Kurtarma parçası {}/{}": "Recovery share {}/{}",
    "{}. parça. Bunu {} kaydet. Herhangi {} parça bir araya gelince kurtarma kodunun yerini "
    "tutar; tek parça hiçbir şey açmaz. Kurtarırken iki parçayı aynı kutuya alt alta yazman "
    "yeterli.": (
        "Share {}. Save it {}. Any {} shares together replace the recovery code; a single share "
        "opens nothing. To recover, type two shares one below the other in the same box."
    ),
    "{}. grup:": "Group {}:",
    "{}. parçada yazım hatası var": "Share {} has a typo",
    # --- Running programs and vault commands (runner.py) ---------------------------------------
    "Çalıştırılacak komut verilmedi": "No command to run was given",
    "Değeri göstermek": "Show the value",
    "Geçersiz değişken adı veya boş değer": "Invalid variable name or empty value",
    "Değeri değiştirmek": "Change the value",
    "Dosyadaki __SECURE_..__ etiketini yazın ('vault list' gösterir)": (
        "Type the __SECURE_..__ label from the file ('vault list' shows them)"
    ),
    "Programı çalıştırmak": "Run the program",
    "Komut başlatılamadı: {}": "Could not start the command: {}",
    "Kasada böyle bir değişken yok: {}. Karalanmış veriler için dosyadaki __SECURE_..__ "
    "etiketini yazın ('vault list' hepsini gösterir)": (
        "No such variable in the vault: {}. For redacted data type the __SECURE_..__ label from "
        "the file ('vault list' shows all)"
    ),
    "Kasadan kalıcı olarak silmek": "Permanently delete from the vault",
    ".env.sealed içindeki {} kasada bulunamadı": "{} from .env.sealed was not found in the vault",
    "Bu değer zaten {} adıyla kasada": "This value is already in the vault as {}",
    "Kasada böyle bir kayıt yok: {}": "No such entry in the vault: {}",
    "{} hâlâ kullanılıyor ({}); silinirse bu dosyalar çalışmaz. Yine de silmek için: --force": (
        "{} is still used ({}); these files break if it is deleted. To delete anyway: --force"
    ),
    # --- File safety ---------------------------------------------------------------------
    "Hassas yol varsayılan olarak hariç": "Sensitive path, excluded by default",
    "Normal dosya değil": "Not a regular file",
    "Boyut sınırı aşıldı": "Size limit exceeded",
    "Binary dosya atlandı": "Binary file skipped",
    "Çalışma dizini bulunamadı": "Working directory not found",
    "Geçersiz dosya yolu": "Invalid file path",
    "Mutlak yollar kabul edilmez": "Absolute paths are not accepted",
    "Yolda ':' karakteri kabul edilmez": "':' is not accepted in paths",
    "Çalışma dizini dışına çıkılamaz": "Cannot leave the working directory",
    "Dosya bulunamadı": "File not found",
    "Sembolik bağlantı veya junction izlenmez": "Symbolic links and junctions are not followed",
    "UTF-8 olmayan dosya atlandı": "Non-UTF-8 file skipped",
    "Dosya başka bir işlem tarafından kilitli: {}": "File is locked by another process: {}",
    "Hassas yola yazılamaz: {}": "Cannot write to a sensitive path: {}",
    "Dosya iş başladıktan sonra değişmiş, üzerine yazılmadı: {}": (
        "File changed after the job started, not overwritten: {}"
    ),
    # --- Sealing (sealer.py) -------------------------------------------------------------
    "Kasada böyle bir etiket yok ('vault list' hepsini gösterir)": (
        "No such label in the vault ('vault list' shows all)"
    ),
    "Bu değer zaten {} adıyla çalışırken veriliyor": "This value is already provided at runtime as {}",
    "Geçersiz değişken adı: {}": "Invalid variable name: {}",
    "{} adı kasada başka bir değere bağlı": "The name {} is bound to another value in the vault",
    "Karalama doğrulanamadı, dosya yazılmadı: {}": "Redaction could not be verified, file not written: {}",
    "Dosya karalama sırasında değişmiş: {}": "File changed during redaction: {}",
    "UTF-8 olmayan dosya": "Non-UTF-8 file",
    "{} başka bir dosyada farklı değerle de vardı; çalışırken {} içindeki değer verilecek": (
        "{} also exists with a different value in another file; at runtime the value from {} is used"
    ),
    "Aynı değer zaten {} adıyla kasada": "The same value is already in the vault as {}",
    "bu dosya türü otomatik desteklenmiyor": "this file type is not supported automatically",
    "değer daha büyük bir metnin parçası": "the value is part of a larger string",
    "Ayar dosyasında karalandı; uygulama bu değeri {} ortam değişkeninden okumalı": (
        "Redacted in a config file; the app should read this value from the {} environment variable"
    ),
    "Elle taşınmalı ({}); dosyada bırakıldı": "Must be moved by hand ({}); left in the file",
    # --- Team (team.py) ----------------------------------------------------------------
    "sahip": "owner",
    "üye": "member",
    ".gitignore dosyası {} klasörünü dışarıda bırakıyor; arkadaşın kasayı alamaz. .gitignore'dan "
    "'{}/' satırını kaldırın (yedekler ve kilitler {}/.gitignore ile zaten dışarıda kalır).": (
        ".gitignore excludes the {} folder, so teammates cannot get the vault. Remove the '{}/' "
        "line from .gitignore (backups and locks stay out via {}/.gitignore)."
    ),
    "Bu bilgisayarın SSH anahtarı ekipte kayıtlı değil": "This computer's SSH key is not in the team",
    "Desteklenmeyen SSH anahtarı": "Unsupported SSH key",
    "Geçersiz GitHub kullanıcı adı: {}": "Invalid GitHub username: {}",
    "@{} GitHub hesabına ed25519 ya da RSA (≥2048) SSH anahtarı eklememiş": (
        "@{} has no ed25519 or RSA (≥2048) SSH key on their GitHub account"
    ),
    "Bu SSH anahtarı bu bilgisayarda yok": "This SSH key is not on this computer",
    "SSH şifresi 3 kez yanlış girildi": "Wrong SSH passphrase 3 times",
    "Bu projede ekip kurulmamış; önce: team init --github <kullanıcı adın>": (
        "No team in this project; first: team init --github <your username>"
    ),
    "Bu projede ekip zaten kurulu ('team list' üyeleri gösterir)": (
        "This project already has a team ('team list' shows members)"
    ),
    "Bu bilgisayarda SSH anahtarı yok (~/.ssh/id_ed25519 ve .pub). Oluştur: ssh-keygen -t "
    "ed25519 (şifre koy), sonra .pub içeriğini GitHub → Settings → SSH keys'e ekle": (
        "No SSH key on this computer (~/.ssh/id_ed25519 and .pub). Create one: ssh-keygen -t "
        "ed25519 (set a passphrase), then add the .pub content under GitHub → Settings → SSH keys"
    ),
    "Bu bilgisayardaki SSH anahtarı @{} GitHub hesabında yok. Önce .pub içeriğini GitHub → "
    "Settings → SSH keys'e ekle.": (
        "This computer's SSH key is not on @{}'s GitHub account. First add the .pub content under "
        "GitHub → Settings → SSH keys."
    ),
    "Ekip kurmak (sen sahip olursun)": "Set up a team (you become the owner)",
    "@{} kullanıcısına kasa erişimi vermek ({})": "Give @{} access to the vault ({})",
    "@{} ekipte değil": "@{} is not in the team",
    "@{} kullanıcısını sahip yapmak": "Make @{} an owner",
    "Son sahip çıkarılamaz; önce başka birini sahip yapın": (
        "The last owner cannot be removed; make someone else an owner first"
    ),
    "@{} kullanıcısını ekipten çıkarmak (kasa anahtarı yenilenir)": (
        "Remove @{} from the team (the vault key is rotated)"
    ),
    "GitHub yanıt vermedi (HTTP {})": "GitHub did not respond (HTTP {})",
    "GitHub'a ulaşılamadı; internet bağlantısını kontrol edin": (
        "Could not reach GitHub; check your internet connection"
    ),
    "SSH anahtarın şifresiz: {}\nŞifresiz anahtarı bilgisayardaki herhangi bir program "
    '(ajanlar dahil) okuyabilir. Şifre ekle: ssh-keygen -p -f "{}"': (
        "Your SSH key has no passphrase: {}\nAny program on this computer (agents included) can "
        'read an unencrypted key. Add one: ssh-keygen -p -f "{}"'
    ),
    "Şifre yanlış. ": "Wrong passphrase. ",
    "team.json bu kasanın anahtarıyla uyuşmuyor": "team.json does not match this vault's key",
    "GitHub'da @{} adında kullanıcı yok": "There is no GitHub user named @{}",
    "SSH anahtarı okunamadı: {}": "Could not read the SSH key: {}",
    "SSH anahtarı": "SSH key",
    "{} anahtarının şifresi (kasayı açmak için):": "Passphrase for {} (to open the vault):",
    "SSH şifresi girilmedi; kasa açılmadı": "No SSH passphrase entered; the vault was not opened",
    "Desteklenmeyen SSH anahtarı türü": "Unsupported SSH key type",
    "team.json bozuk ya da tanınmayan biçimde": "team.json is corrupted or in an unknown format",
    "team.json'daki @{} kaydı doğrulanamadı (elle değiştirilmiş olabilir)": (
        "The @{} entry in team.json could not be verified (it may have been edited by hand)"
    ),
    "@{} bu projede üye; bu işlemi yalnızca sahipler yapabilir": (
        "@{} is a member of this project; only owners can do this"
    ),
    # --- CLI help infrastructure (cli_help.py) --------------------------------------------------
    "Örnekler": "Examples",
    "hata": "error",
    "Yardım için: {} --help": "For help: {} --help",
    "'{}' diye bir komut yok. Bunu mu demek istediniz: {}?": "There is no '{}' command. Did you mean: {}?",
    "'{}' diye bir komut yok. Komutlar: {}": "There is no '{}' command. Commands: {}",
    "geçersiz değer '{}' (seçenekler: {})": "invalid value '{}' (choices: {})",
    # --- CLI: main help and command groups -------------------------------------------------
    "Sırları dosyalardan çıkarıp şifreli bir kasaya mühürler: yapay zekâ ajanları\n"
    "dosyalarını okusa da şifre göremez. Program çalışırken sırlar onaylı verilir.": (
        "Moves secrets out of your files and seals them in an encrypted vault: AI agents\n"
        "can read your files but never see a password. Secrets are handed over, with your\n"
        "approval, only while your program runs."
    ),
    "Bir komutun ayrıntısı ve örnekleri: sealbox help <komut>  (ya da sealbox <komut> --help)\n"
    "Dil: --lang tr|en ya da SEALBOX_LANG ortam değişkeni.": (
        "Details and examples for a command: sealbox help <command>  (or sealbox <command> --help)\n"
        "Language: --lang tr|en or the SEALBOX_LANG environment variable."
    ),
    "sealbox [--lang tr|en] <komut> [seçenekler]": "sealbox [--lang tr|en] <command> [options]",
    "Mesaj dili (varsayılan: bilgisayarın dili)": "Message language (default: your system language)",
    "<komut>": "<command>",
    "KLASÖR": "FOLDER",
    "DOSYA": "FILE",
    "KULLANICI": "USER",
    "AD": "NAME",
    "<işlem>": "<action>",
    "Başlarken": "Getting started",
    "Günlük kullanım": "Everyday use",
    "Ekip": "Team",
    "Kurtarma": "Recovery",
    "Projeyi kontrol et, ne yapman gerektiğini adım adım söyle": (
        "Check the project and tell you what to do, step by step"
    ),
    "Kasa, anahtar, kurtarma ve ekip durumu": "Vault, key, recovery and team status",
    "Dosyalardaki sırları kasaya taşı (mühürle)": "Move secrets from your files into the vault (seal)",
    "Programı sırlarla çalıştır (her seferinde onay)": "Run your program with its secrets (approved each time)",
    "Kasadaki değerleri listele, göster, değiştir, sil": "List, show, change and delete vault values",
    "Kasayı GitHub SSH anahtarlarıyla arkadaşlarınla paylaş": (
        "Share the vault with teammates via their GitHub SSH keys"
    ),
    "Anahtar kaybolursa kasayı geri açan kurtarma kodu": (
        "A recovery code that reopens the vault if the key is lost"
    ),
    # --- Shared options ----------------------------------------------------------------------
    "Proje kökü (varsayılan: bulunduğun klasör)": "Project root (default: current folder)",
    "sealbox.toml yolu": "Path to sealbox.toml",
    "Proje kökü": "Project root",
    "Proje kökü (varsayılan: kasası olan üst klasör)": (
        "Project root (default: the nearest parent folder with a vault)"
    ),
    "Raporu JSON bas": "Print the report as JSON",
    "Raporu JSON bas (editör eklentisi)": "Print the report as JSON (editor extension)",
    # --- init / status --------------------------------------------------------------------
    "Projeyi kontrol eder ve sıradaki adımları sırayla söyler. Hiçbir dosyayı\n"
    "değiştirmez; yeni bir projede ilk çalıştırılacak komuttur.": (
        "Checks the project and lists your next steps in order. Changes no files;\n"
        "this is the first command to run in a new project."
    ),
    "bulunduğun klasördeki projeyi kontrol et": "check the project in the current folder",
    "başka bir klasördeki projeyi kontrol et": "check a project in another folder",
    "Kasanın, anahtarın, kurtarma kodunun ve ekibin durumunu gösterir. Sorun olan\n"
    "her satırın yanında ne yapman gerektiği yazar. Bir şey açılamıyorsa çıkış kodu 1.": (
        "Shows the state of the vault, its key, the recovery code and the team. Each line\n"
        "with a problem says what to do. Exit code 1 if something cannot be opened."
    ),
    "durumu göster": "show the status",
    "betikler ve CI için makine okunur çıktı": "machine-readable output for scripts and CI",
    "Proje: {}": "Project: {}",
    "sealbox {} · proje: {}": "sealbox {} · project: {}",
    "⚠ Üst klasörde {}: {} — proje kökü orası olabilir (cd ile geç).": (
        "⚠ The parent folder {}: {} — that may be the project root (cd there)."
    ),
    "Her şey hazır. Programını çalıştırmak için: sealbox exec -- <komut>": (
        "All set. To run your program: sealbox exec -- <command>"
    ),
    "Sıradaki adımlar:": "Next steps:",
    "Sonra kasayı repoya ekle: git add {} && git commit": (
        "Then add the vault to your repo: git add {} && git commit"
    ),
    "Her komutun ayrıntısı: sealbox help <komut>": "Details for each command: sealbox help <command>",
    "Diskte açık sır yok": "No exposed secrets on disk",
    "{} dosyada bilgi notu var": "Notes in {} file(s)",
    "{} dosyada açık sır var": "Exposed secrets in {} file(s)",
    "Bu projede henüz kasa yok": "This project has no vault yet",
    "Kasa: {} değişken, {} karalanmış veri ({})": "Vault: {} variables, {} redacted values ({})",
    "Kasa anahtarı bu bilgisayarda": "The vault key is on this computer",
    "Kasa anahtarı bu bilgisayarda yok; ilk açılışta SSH şifren sorulacak": (
        "The vault key is not on this computer yet; your SSH passphrase is asked on first open"
    ),
    "Kasa anahtarı bu bilgisayarda yok": "The vault key is not on this computer",
    "Ekip: {} kişi": "Team: {} people",
    "Ekip kurulmamış (tek kişi)": "No team (single user)",
    "Kasa klasörünün .gitignore dosyası eksik": "The vault folder's .gitignore is incomplete",
    "Kurtarma kodu yok: anahtar kaybolursa kasa açılamaz": (
        "No recovery code: if the key is lost the vault cannot be opened"
    ),
    "Kurtarma kurulu ama bu proje henüz ona kilitlenmedi": (
        "Recovery is set up but this project is not locked to it yet"
    ),
    "Kurtarma kodu kurulu": "Recovery code is set up",
    # --- seal ---------------------------------------------------------------------------------
    "Dosyalardaki parola, token, API anahtarı ve kişisel verileri bulur:\n"
    "  - kod içindeki sırları kasaya taşır, yerine ortam değişkeni okuması yazar\n"
    "    (Python os.environ, JS/TS process.env, Java System.getenv),\n"
    "  - e-posta, TCKN gibi verileri __SECURE_..__ etiketiyle karalar,\n"
    "  - .env dosyasını kasaya alır, yerine .env.sealed bırakır.\n"
    "Yazmadan önce bakmak için --check kullan.": (
        "Finds passwords, tokens, API keys and personal data in your files:\n"
        "  - moves secrets in code into the vault and writes an environment variable read\n"
        "    in their place (Python os.environ, JS/TS process.env, Java System.getenv),\n"
        "  - redacts data such as e-mail addresses and IDs with a __SECURE_..__ label,\n"
        "  - takes .env into the vault and leaves .env.sealed in its place.\n"
        "Use --check to look before writing."
    ),
    "yalnızca bak: diskte açık sır var mı?": "only look: are there exposed secrets on disk?",
    "tüm projedeki sırları kasaya taşı": "move all secrets in the project into the vault",
    "yalnızca bir dosya": "a single file",
    "Dosya/klasör (varsayılan: tüm proje)": "File/folder (default: the whole project)",
    "Yazma; sır varsa çıkış kodu 1": "Do not write; exit code 1 if secrets are found",
    "Bu klasörde veya üstünde kasa yok; önce 'seal' çalıştırın": (
        "No vault in this folder or above; run 'seal' first"
    ),
    "Üst klasörde {}: {}\nProje kökü orası gibi görünüyor; komutu o klasörden çalıştırın. Bu "
    "klasörü bilerek seçiyorsanız: -w .": (
        "The parent folder {}: {}\nThat looks like the project root; run the command from there. "
        "If you chose this folder on purpose: -w ."
    ),
    "{} değer kasaya taşındı ({})": "{} value(s) moved to the vault ({})",
    "{} değer karalandı": "{} value(s) redacted",
    "değişiklik yok": "no changes",
    "  [{}] satır {} ({}): {}": "  [{}] line {} ({}): {}",
    "{} dosya tarandı ({} sn).": "{} file(s) scanned ({} s).",
    "Temiz: diskte karalanmamış sır bulunmadı.": "Clean: no unredacted secrets on disk.",
    "Diskte karalanmamış sır var. 'sealbox seal' çalıştırın.": (
        "There are unredacted secrets on disk. Run 'sealbox seal'."
    ),
    "Tamam: {} dosya yazıldı. Kasa: {}": "Done: {} files written. Vault: {}",
    "Programı artık şöyle çalıştırın: sealbox exec -- <komut>": (
        "From now on run your program like this: sealbox exec -- <command>"
    ),
    "Taşınacak sır bulunamadı.": "No secrets to move.",
    # --- exec ---------------------------------------------------------------------------------
    "Programını kasadaki sırlarla çalıştırır. Önce hangi değerlerin verileceğini\n"
    "gösteren bir onay penceresi açılır; sırlar yalnızca bu çalıştırmaya ortam\n"
    "değişkeni olarak verilir. Programın çıktısındaki sırlar [GİZLİ:..] olarak basılır.": (
        "Runs your program with the secrets from the vault. An approval window first shows\n"
        "which values will be handed over; they are given only to this run, as environment\n"
        "variables. Secrets in the program's output are printed as [REDACTED:..]."
    ),
    "Maven / Gradle da olur": "Maven / Gradle work too",
    "-- ardından çalıştırılacak komut": "The command to run, after --",
    # --- vault --------------------------------------------------------------------------------
    "Kasadaki kayıtları yönetir. Değerler hiçbir zaman terminale kendiliğinden\n"
    "yazılmaz; göstermek ve değiştirmek onay ister.": (
        "Manages vault entries. Values are never printed to the terminal on their own;\n"
        "showing and changing them requires approval."
    ),
    "değişken adları ve etiketler (değer yok)": "variable names and labels (no values)",
    "bir değeri göster (onay ister)": "show a value (asks for approval)",
    "değeri değiştir ya da ekle": "change or add a value",
    "hiçbir dosyanın kullanmadığı kayıtları sil": "delete entries no file uses",
    "Değişken adları (değer göstermez)": "Variable names (no values shown)",
    "Değeri göster (onay ister)": "Show the value (asks for approval)",
    "Değeri değiştir/ekle": "Change/add the value",
    "Karalanmış veriyi programa çalışırken ver (TCKN, e-posta...)": (
        "Give redacted data to the program at runtime (IDs, e-mail...)"
    ),
    "Dosyadaki __SECURE_..__ etiketi": "The __SECURE_..__ label in the file",
    "Ortam değişkeni adı (varsayılan: atamadan)": "Environment variable name (default: from the assignment)",
    "Kasadan kayıt sil (onay ister)": "Delete an entry from the vault (asks for approval)",
    "Değişken adı veya __SECURE_..__ etiketi": "Variable name or __SECURE_..__ label",
    "Hiçbir dosyanın kullanmadığı kayıtlar": "Entries no file uses",
    "Dosyada kullanılıyor olsa da sil": "Delete even if a file still uses it",
    "Anahtar kayıpsa: yeni boş kasa aç (eskisi kenara kaldırılır)": (
        "If the key is lost: start a new empty vault (the old one is set aside)"
    ),
    "\nKaralanmış veriler (bakmak için: vault reveal <etiket>):": (
        "\nRedacted data (to look: vault reveal <label>):"
    ),
    "Tamam: değer artık çalışırken {} olarak verilecek.": "Done: the value is now given at runtime as {}.",
    "  {}: etiket {} okumasına çevrildi": "  {}: label replaced with a read of {}",
    "Silinecek adı/etiketi yazın ya da --unused kullanın": "Give a name/label to delete, or use --unused",
    "Silinecek kullanılmayan kayıt yok.": "No unused entries to delete.",
    "Silindi: {}": "Deleted: {}",
    "{} için yeni değer (ekranda görünmez): ": "New value for {} (not shown on screen): ",
    "{} eklendi.": "{} added.",
    "{} güncellendi.": "{} updated.",
    "Kasayı sıfırlamak (eski kasa silinmez, kenara kaldırılır; değerleri yeniden girersin)": (
        "Reset the vault (the old vault is not deleted but set aside; you re-enter the values)"
    ),
    "{} karalanmış veri": "{} redacted values",
    "Yeni boş kasa açıldı. Eski kasa {}/lost-<tarih>/ içinde duruyor.": (
        "A new empty vault was created. The old vault is in {}/lost-<date>/."
    ),
    "\nDeğeri kaybolan değişkenler (servis panelinden yeni değer alıp gir):": (
        "\nVariables whose values were lost (get new values from each service's dashboard):"
    ),
    "\nDeğeri kaybolan karalanmış veriler (asıl kaynağından al, dosyada etiketin yerine yaz ve "
    "tekrar 'seal' çalıştır):": (
        "\nRedacted data whose values were lost (get them from the original source, put them in "
        "place of the label and run 'seal' again):"
    ),
    "\nKurtarma kodu kuruluysa yeni kasa ona kendiliğinden kilitlendi.": (
        "\nIf a recovery code is set up, the new vault was locked to it automatically."
    ),
    # --- team ---------------------------------------------------------------------------------
    "Kasayı arkadaşlarınla paylaşır. Kasa repoya girer; değerleri yalnızca ekipteki\n"
    "GitHub hesaplarının SSH anahtarları açabilir. Değişiklikten sonra commit + push et.": (
        "Shares the vault with teammates. The vault goes into the repo; only the SSH keys of\n"
        "the team's GitHub accounts can open its values. Commit + push after each change."
    ),
    "ekibi kur (sen sahip olursun)": "set up the team (you become the owner)",
    "github.com/arkadasim.keys ile erişim ver": "give access using github.com/arkadasim.keys",
    "sahip olarak ekle": "add as an owner",
    "çıkar; kasa anahtarı yenilenir": "remove; the vault key is rotated",
    "üyeler": "members",
    "Ekibi kur (sen sahip olursun)": "Set up the team (you become the owner)",
    "Senin GitHub kullanıcı adın": "Your GitHub username",
    "GitHub kullanıcısına erişim ver": "Give a GitHub user access",
    "Sahip olarak ekle": "Add as an owner",
    "Ekipten çıkar (kasa anahtarı yenilenir)": "Remove from the team (the vault key is rotated)",
    "Sahip yap": "Make an owner",
    "Üyeler ve SSH parmak izleri": "Members and SSH fingerprints",
    "Bu projede ekip kurulmamış. Kurmak için: team init --github <kullanıcı adın>": (
        "No team in this project. To set one up: team init --github <your username>"
    ),
    "Ekip kuruldu: @{} sahip ({} SSH anahtarı).": "Team set up: @{} is the owner ({} SSH keys).",
    "@{} eklendi ({}, {} SSH anahtarı).": "@{} added ({}, {} SSH keys).",
    "Şimdi commit + push et; @{} pull edince kasayı kendi SSH anahtarıyla açar.": (
        "Now commit + push; after pulling, @{} opens the vault with their own SSH key."
    ),
    "@{} artık sahip. Commit + push et.": "@{} is now an owner. Commit + push.",
    "@{} çıkarıldı ve kasa anahtarı yenilendi. Commit + push et.": (
        "@{} was removed and the vault key rotated. Commit + push."
    ),
    "@{} bunları daha önce görmüş olabilir; mümkünse servislerinden yenileyin:": (
        "@{} may have seen these before; rotate them at their services if you can:"
    ),
    "Uyarı: {}": "Warning: {}",
    # --- recovery -----------------------------------------------------------------------------
    "Kasa anahtarı kaybolursa (Windows sıfırlama, yeni bilgisayar) kasayı geri açan\n"
    "kurtarma kodu. Kod ve parçalar yalnızca pencerede gösterilir, terminale yazılmaz.": (
        "A recovery code that reopens the vault if its key is lost (Windows reset, new\n"
        "computer). The code and its shares are only shown in a window, never in the terminal."
    ),
    "kurtarma kodunu üret (bir kez)": "create your recovery code (once)",
    "kodu 3 parçaya böl; herhangi 2'si yeter": "split the code into 3 shares; any 2 are enough",
    "kurtarma kiti (USB / bulut için)": "recovery kit (for USB / cloud)",
    "kod ya da 2 parçayla anahtarı geri getir": "bring the key back with the code or 2 shares",
    "kasa klasörü de gittiyse": "if the vault folder is gone too",
    "Kurtarma kodu üret (pencerede gösterilir)": "Create a recovery code (shown in a window)",
    "Var olan kodu yenisiyle değiştir": "Replace the existing code with a new one",
    "Kodu 2-of-3 parçaya böl": "Split the code into 2-of-3 shares",
    "Kod ya da parçalarla anahtarı geri getir": "Bring the key back with the code or shares",
    "Kurtarma kiti dosyası (yeni bilgisayar / silinmiş kasa)": (
        "Recovery kit file (new computer / deleted vault)"
    ),
    "Kurtarma kiti dosyası yaz (USB/bulut)": "Write a recovery kit file (USB/cloud)",
    "Kurtarma kurulu mu": "Is recovery set up?",
    "Kurtarma kurulmamış: kasa anahtarı kaybolursa kasalar açılamaz.": (
        "Recovery is not set up: if the vault key is lost, vaults cannot be opened."
    ),
    "Kurmak için: sealbox recovery setup": "To set it up: sealbox recovery setup",
    "Kurtarma kurulu. Bu proje korunuyor.": "Recovery is set up. This project is protected.",
    "Kurtarma kurulu.": "Recovery is set up.",
    "Kurtarma kuruldu. Kod yalnızca pencerede gösterildi.": (
        "Recovery is set up. The code was shown only in the window."
    ),
    "Bu proje kurtarma koduna kilitlendi; diğer projeler açıldıkça kilitlenir.": (
        "This project is locked to the recovery code; other projects follow as they are opened."
    ),
    "{} parça gösterildi; herhangi {} tanesi kodun yerini tutar.": (
        "{} shares were shown; any {} of them replace the code."
    ),
    "Kasa geri geldi ({} kayıt). Anahtar bu bilgisayarın kimlik deposuna yazıldı.": (
        "The vault is back ({} entries). The key was saved to this computer's credential store."
    ),
    "Bu klasörde veya üstünde kasa yok": "No vault in this folder or above",
    "Kurtarma kiti yazıldı: {}": "Recovery kit written: {}",
    "Kit kurtarma kodu olmadan açılmaz; USB'ye ya da buluta koyabilirsin.": (
        "The kit cannot be opened without the recovery code; you can keep it on USB or in the cloud."
    ),
    # --- Secrets left exposed in files (seal / status) ------------------------------------------
    "DİKKAT: {} sır dosyada AÇIK kaldı ": "WARNING: {} secret(s) left OPEN in files ",
    "Ajan bu dosyaları okursa bu değerleri görür. Ne yapmalı:": (
        "An agent that reads these files will see these values. What to do:"
    ),
    "  - Metnin içindeyse (ör. URL'deki parola): sırrı ayrı bir değişkene al,": (
        "  - Inside a larger text (e.g. a password in a URL): move the secret to its own variable"
    ),
    "    metni o değişkenle kur. Örnek (Python):": (
        "    and build the text from it. Example (Python):"
    ),
    "    Sonra değeri kasaya ekle: sealbox vault set DB_PASSWORD": (
        "    Then add the value to the vault: sealbox vault set DB_PASSWORD"
    ),
    "  - Desteklenmeyen dosyadaysa: değeri sil, aynı yolla ortam değişkeninden oku.": (
        "  - In an unsupported file: delete the value and read it from an environment variable."
    ),
    "{} sır dosyada AÇIK kaldı, elle taşınmalı": "{} secret(s) left OPEN in files; move them by hand",
    # --- Git history and commit hook (history.py) -----------------------------------------------
    "Bu klasör bir git deposu değil": "This folder is not a git repository",
    (
        "{} başka bir araca ait; üzerine yazılmadı. O dosyanın sonuna şu satırı ekle: "
        "sealbox hook run -w {}"
    ): (
        "{} belongs to another tool and was not overwritten. Add this line to the end of "
        "that file: sealbox hook run -w {}"
    ),
    "uzak sunucuya gönderilmiş": "pushed to a remote",
    "yalnızca bu bilgisayarda": "only on this computer",
    "  ⚠ {}: {} commit'te açık — {}": "  ⚠ {}: exposed in {} commit(s) — {}",
    "      ilk: {} {}, {}": "      first: {} {}, {}",
    "      → servisinden yenile, sonra: sealbox vault set {}": (
        "      → renew it at the provider, then: sealbox vault set {}"
    ),
    "      → kişisel veri: geçmişten temizlemeyi düşün (git filter-repo)": (
        "      → personal data: consider removing it from history (git filter-repo)"
    ),
    "  Dosyayı temizlemek geçmişi silmez: bu değerler eski commit'lerde okunabilir.": (
        "  Cleaning the file does not erase history: these values can be read in old commits."
    ),
    "  ✓ Kasadaki değerlerin hiçbiri git geçmişinde yok": (
        "  ✓ None of the vault values are in the git history"
    ),
    "Bu klasör bir git deposu değil; taranacak geçmiş yok.": (
        "This folder is not a git repository; there is no history to scan."
    ),
    "Git geçmişi:": "Git history:",
    "Kanca kuruldu: {}": "Hook installed: {}",
    "Kasadaki bir değer commit'e girmeye çalışırsa commit durdurulur.": (
        "If a vault value is about to be committed, the commit is stopped."
    ),
    "Kanca kaldırıldı.": "Hook removed.",
    "Kurulu sealbox kancası yok.": "No sealbox hook is installed.",
    "sealbox: kasa anahtarı yok; commit yalnızca genel kurallarla tarandı": (
        "sealbox: no vault key; the commit was only checked with general rules"
    ),
    "  ⚠ {}:{}  olası sır ({})": "  ⚠ {}:{}  possible secret ({})",
    "✗ sealbox: commit durduruldu, kasadaki değerler bu commit'e giriyor:": (
        "✗ sealbox: commit stopped, vault values are in this commit:"
    ),
    "  Değeri dosyadan çıkar (sealbox seal), 'git add' ile güncelle ve tekrar dene.": (
        "  Take the value out of the file (sealbox seal), 'git add' it again and retry."
    ),
    "Git": "Git",
    "Kasadaki değerler eski commit'lerde açık mı?": "Are vault values exposed in old commits?",
    "Kasadaki bir değer commit'e girmesin (pre-commit kancası)": (
        "Keep vault values out of commits (pre-commit hook)"
    ),
    (
        "Kasadaki değerleri git geçmişinin tamamında arar. Kasaya taşınmadan önce commit\n"
        "edilmiş bir sır eski commit'lerde okunabilir; bulunursa o sırrı servisinden\n"
        "yenile. Değerler ekrana yazılmaz, yalnızca ad, commit ve dosya. Bulursa çıkış kodu 1."
    ): (
        "Searches the whole git history for vault values. A secret committed before it was\n"
        "moved to the vault can still be read in old commits; if one is found, renew it at\n"
        "the provider. Values are never printed, only name, commit and file. Exit code 1 if found."
    ),
    "geçmişi tara": "scan the history",
    (
        "Git'e bir pre-commit kancası kurar: kasadaki bir değer commit'e girmeye çalışırsa\n"
        "commit durdurulur. Kazaya karşı emniyet kemeridir; 'git commit --no-verify'\n"
        "onu atlar. Kanca repoya girmez; ekipteki herkes kendi bilgisayarında kurar."
    ): (
        "Installs a git pre-commit hook: if a vault value is about to be committed, the\n"
        "commit is stopped. It is a seatbelt against accidents; 'git commit --no-verify'\n"
        "skips it. The hook is not part of the repo; everyone on the team installs it locally."
    ),
    "kancayı kur": "install the hook",
    "kancayı kaldır": "remove the hook",
    "Pre-commit kancasını kur": "Install the pre-commit hook",
    "SealBox kancasını kaldır": "Remove the sealbox hook",
    "Kancanın çalıştırdığı kontrol (elle de olur)": "The check the hook runs (can be run by hand)",
    "Commit kancası kurulu": "Commit hook installed",
    "Commit kancası kurulu değil": "Commit hook not installed",
    "Kanca kurulu mu": "Is the hook installed?",
    "Commit kancası yok: kasadaki bir değer yanlışlıkla commit edilebilir": (
        "No commit hook: a vault value could be committed by accident"
    ),
    # --- General -------------------------------------------------------------------------------
    "Beklenmeyen hata: {}": "Unexpected error: {}",
    "Durduruldu: {}": "Stopped: {}",
}
