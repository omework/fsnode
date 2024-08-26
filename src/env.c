//
// Created by Jabar Karim on 25/08/2024.
//

#include "env.h"


/**
 * @brief Load environment variables from the .env file and invoke the callback for each variable.
 *
 * This function reads the .env file and processes each line as an environment variable.
 * Lines starting with '#' or containing only whitespace characters are ignored.
 * Each environment variable is expected to be in the format 'name=value'.
 * The callback function provided by the user is invoked for each valid environment variable,
 * passing the provided container and the env_var_t structure containing the variable name and value.
 *
 * @param container A pointer to the container object that will be passed to the callback function.
 * @param var_cb The callback function to be invoked for each environment variable.
 * @return 0 on success, -1 if there was an error opening the .env file, 1 if the callback function returned false.
 */
int env_load(void *container, env_var_cb var_cb) {
    FILE *env_file = fopen(".env", "r");
    if (env_file == NULL) {
        perror("error opening .env handle");
        return -1;
    }

    env_var_t var;
    size_t line_len = 0;
    bool ok = true;
    while (ok) {
        char *line = NULL;
        if (-1 == getline(&line, &line_len, env_file)) {
            if (line != NULL) free(line);
            break;
        }

        char *clean_line = trim(line);
        free(line);

        if (*clean_line == '#' || *clean_line == '\n' || *clean_line == '\0') {
            free(clean_line);
            continue;
        }

        char *pos;
        char *start;
        pos = start = clean_line;

        while (*pos != '=' && *pos != ':') pos++;
        if (!*pos) {
            free(clean_line);
            break;
        }
        var.name = strndup(start, pos - start);

        pos++;

        while (*pos == ' ') pos++;
        start = pos;

        while (*pos != '\n' && *pos != '\0') pos++;
        var.value = strndup(start, pos - start);

        printf("ENV %s=%s\n", var.name, var.value);

        ok = var_cb(container, var);
        free(clean_line);
        free((char *) var.name);
        if (var.value != NULL) {
            free((char *) var.value);
        }
        if (!ok) {
            return 1;
        }
    }
    fclose(env_file);
    return 0;
}