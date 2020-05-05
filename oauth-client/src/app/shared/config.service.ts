import { Injectable } from '@angular/core';
 
@Injectable()
export class ConfigService {    

    constructor() {}

    get authBaseURI() {
        return 'https://localhost:44330';
    }    
     
    get authApiURI() {
        return `${this.authBaseURI}/api`;
    }    
     
    get resourceApiURI() {
        return 'http://localhost:5050/api';
    }  
}