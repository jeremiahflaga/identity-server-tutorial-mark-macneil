import { Injectable } from '@angular/core';
 
@Injectable()
export class ConfigService {    

    constructor() {}

    get authApiURI() {
        return 'https://localhost:44330/api';
    }    
     
    get resourceApiURI() {
        return 'http://localhost:5050/api';
    }  
}