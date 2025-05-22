#include <security/pam_modules.h>  
#include <security/pam_ext.h> 
#include <security/pam_appl.h> 
#include <pwd.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h> 
#include <sys/stat.h> 

#define CONFIG_DIR ".pam_question" 
#define CONFIG_FILE "config" 
#define MAX_LINE 128 
#define MAX_ANSWER 128 

// Remove o \\n no final da string 

void trim_newline(char *str) { 

    size_t len = strlen(str); 

    if (len > 0 && str[len - 1] == '\n') str[len - 1] = '\0'; 

} 

 

// Cria o diretório ~/.pam_question se não existir 

void ensure_config_dir(const char *home) { 

    char path[512]; 

    snprintf(path, sizeof(path), "%s/%s", home, CONFIG_DIR); 

    mkdir(path, 0700); // Só o dono pode acessar 

} 

 

// Caminho completo para ~/.pam_question/config 

void get_config_path(const char *home, char *out_path, size_t size) { 

    snprintf(out_path, size, "%s/%s/%s", home, CONFIG_DIR, CONFIG_FILE); 

} 

 

// Pede uma entrada ao usuário 

int ask_user(pam_handle_t *pamh, const char *prompt, int echo, char *out, size_t out_size) { 

    const struct pam_conv *conv; 

    struct pam_message msg; 

    const struct pam_message *msgp; 

    struct pam_response *resp; 

 

    pam_get_item(pamh, PAM_CONV, (const void **)&conv); 

    msg.msg_style = echo ? PAM_PROMPT_ECHO_ON : PAM_PROMPT_ECHO_OFF; 

    msg.msg = prompt; 

    msgp = &msg; 

 

    int ret = conv->conv(1, &msgp, &resp, conv->appdata_ptr); 

    if (ret != PAM_SUCCESS || resp == NULL || resp->resp == NULL) 

        return PAM_CONV_ERR; 

 

    strncpy(out, resp->resp, out_size); 

    free(resp->resp); 

    free(resp); 

    return PAM_SUCCESS; 

} 

 

// Lê pergunta e resposta do arquivo config 

int read_question_file(const char *filepath, char *pergunta, char *resposta) { 

    FILE *file = fopen(filepath, "r"); 

    if (!file) return -1; 

 

    char line[MAX_LINE]; 

    while (fgets(line, sizeof(line), file)) { 

        trim_newline(line); 

        if (strncmp(line, "pergunta=", 9) == 0) { 

            strncpy(pergunta, line + 9, MAX_LINE); 

        } else if (strncmp(line, "resposta=", 9) == 0) { 

            strncpy(resposta, line + 9, MAX_ANSWER); 

        } 

    } 

 

    fclose(file); 

    return 0; 

} 

 

// Salva pergunta e resposta no arquivo config 

int write_question_file(const char *filepath, const char *pergunta, const char *resposta) { 

    FILE *file = fopen(filepath, "w"); 

    if (!file) return -1; 

    fprintf(file, "pergunta=%s\nresposta=%s\n", pergunta, resposta); 

    fclose(file); 

    chmod(filepath, 0600); // Só o usuário pode ler/escrever 

    return 0; 

} 

 

// Função principal de autenticação 

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) { 

    const char *username; 

    struct passwd *pwd; 

    char pergunta[MAX_LINE] = ""; 

    char resposta[MAX_ANSWER] = ""; 

    char resposta_usuario[MAX_ANSWER] = ""; 

    char filepath[512]; 

 

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) 

        return PAM_AUTH_ERR; 

 

     //Root não precisa da autenticação 

    if (strcmp(username, "root") == 0) 

        return PAM_SUCCESS; 

 

    pwd = getpwnam(username); 

    if (!pwd) return PAM_AUTH_ERR; 

 

    ensure_config_dir(pwd->pw_dir); 

    get_config_path(pwd->pw_dir, filepath, sizeof(filepath)); 

 

    // Se o arquivo não existir, pede pergunta e resposta e salva 

    if (access(filepath, F_OK) != 0) { 

        char nova_pergunta[MAX_LINE], nova_resposta[MAX_ANSWER]; 

 

        if (ask_user(pamh, "Defina uma pergunta pessoal: ", 1, nova_pergunta, sizeof(nova_pergunta)) != PAM_SUCCESS) 

            return PAM_AUTH_ERR; 

        if (ask_user(pamh, "Resposta para a pergunta: ", 1, nova_resposta, sizeof(nova_resposta)) != PAM_SUCCESS) 

            return PAM_AUTH_ERR; 

 

        write_question_file(filepath, nova_pergunta, nova_resposta); 

        return PAM_SUCCESS; 

    } 

 

    // Caso já exista, carregue e compare 

    if (read_question_file(filepath, pergunta, resposta) != 0) 

        return PAM_AUTH_ERR; 

 

    if (ask_user(pamh, pergunta, 1, resposta_usuario, sizeof(resposta_usuario)) != PAM_SUCCESS) 

        return PAM_AUTH_ERR; 

 

    trim_newline(resposta); 

    trim_newline(resposta_usuario); 

 

    if (strcmp(resposta, resposta_usuario) == 0) 

        return PAM_SUCCESS; 

 

    return PAM_AUTH_ERR; 

} 

 

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) { 

    return PAM_SUCCESS; 

} 

 

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { 

    return PAM_SUCCESS; 

} 

 

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) { 

    return PAM_SUCCESS; 

} 
